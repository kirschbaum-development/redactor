<?php

declare(strict_types=1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Http;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Scanner\Scanner;
use Kirschbaum\Redactor\Verification\SecretVerifier;
use Kirschbaum\Redactor\Verification\VerificationResult;
use Kirschbaum\Redactor\Verification\VerificationStatus;
use Kirschbaum\Redactor\Verification\Verifier;
use Kirschbaum\Redactor\Verification\Verifiers\GitHubTokenVerifier;
use Kirschbaum\Redactor\Verification\Verifiers\SlackTokenVerifier;
use Kirschbaum\Redactor\Verification\Verifiers\StripeKeyVerifier;

/**
 * Records what it was asked to check, so tests can prove a secret never left.
 */
class SpyVerifier implements Verifier
{
    /** @var array<int, string> */
    public static array $seen = [];

    public function __construct(
        private readonly VerificationStatus $status = VerificationStatus::Active,
    ) {}

    public function name(): string
    {
        return 'spy';
    }

    public function host(): string
    {
        return 'spy.invalid';
    }

    public function supports(string $entity, string $rule): bool
    {
        return true;
    }

    public function verify(string $secret): VerificationResult
    {
        self::$seen[] = $secret;

        return match ($this->status) {
            VerificationStatus::Active => VerificationResult::active(),
            VerificationStatus::Inactive => VerificationResult::inactive(),
            VerificationStatus::Unknown => VerificationResult::unknown(),
        };
    }
}

function secretFile(string $contents): string
{
    $dir = sys_get_temp_dir().'/redactor_verify_'.uniqid();
    mkdir($dir);
    file_put_contents($dir.'/app.env', $contents);

    return $dir.'/app.env';
}

describe('Verification is off unless three things agree', function () {
    it('stays off when config does not enable it', function () {
        expect(SecretVerifier::fromConfig(['enabled' => false, 'verifiers' => ['github_token']]))->toBeNull();
    });

    it('stays off when enabled but no provider is allowed', function () {
        // Enabling the feature and choosing who to trust are separate
        // decisions; an empty list means none, not all.
        expect(SecretVerifier::fromConfig(['enabled' => true, 'verifiers' => []]))->toBeNull()
            ->and(SecretVerifier::fromConfig(['enabled' => true]))->toBeNull();
    });

    it('runs only the providers on the allowlist', function () {
        $verifier = new SecretVerifier(['github_token']);

        $names = array_map(fn (Verifier $v) => $v->name(), $verifier->enabled());

        expect($names)->toBe(['github_token'])
            ->and($verifier->canVerify('github_token', 'github_token'))->toBeTrue()
            ->and($verifier->canVerify('stripe_key', 'api_key_stripe'))->toBeFalse();
    });

    it('names every host it would contact', function () {
        $verifier = new SecretVerifier(['github_token', 'stripe_key', 'slack_token']);

        expect($verifier->hosts())->toBe(['api.github.com', 'api.stripe.com', 'slack.com']);
    });

    it('reports Unknown rather than silently skipping an unsupported entity', function () {
        $result = (new SecretVerifier(['github_token']))->verify('stripe_key', 'api_key_stripe', 'sk_live_x');

        expect($result->status)->toBe(VerificationStatus::Unknown)
            ->and($result->note)->toContain('No verifier is enabled');
    });

    it('degrades to Unknown when a verifier throws', function () {
        $exploding = new class implements Verifier
        {
            public function name(): string
            {
                return 'boom';
            }

            public function host(): string
            {
                return 'boom.invalid';
            }

            public function supports(string $e, string $r): bool
            {
                return true;
            }

            public function verify(string $s): VerificationResult
            {
                throw new \RuntimeException('network on fire');
            }
        };

        $result = (new SecretVerifier(['boom'], [$exploding]))->verify('x', 'y', 'secret');

        expect($result->status)->toBe(VerificationStatus::Unknown)
            ->and($result->note)->toContain('network on fire');
    });
});

describe('Verification never leaks the secret', function () {
    afterEach(fn () => SpyVerifier::$seen = []);

    it('keeps the secret out of the finding and its output', function () {
        SpyVerifier::$seen = [];

        $path = secretFile("GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n");

        $scanner = (new Scanner(app(Redactor::class)))
            ->withVerifier(new SecretVerifier(['spy'], [new SpyVerifier]));

        $result = $scanner->scanFile($path, 'file_scan');

        $encoded = json_encode(array_map(fn ($f) => $f->toArray(), $result->findings));

        // The verifier saw it - that is its job - but nothing that gets written
        // out did.
        expect(SpyVerifier::$seen)->not->toBeEmpty()
            ->and($encoded)->not->toContain('ghp_abcdefghijklmnopqrstuvwxyz0123456789');

        cleanupDirectory(dirname($path));
    });

    it('sends nothing at all when no verifier is attached', function () {
        SpyVerifier::$seen = [];

        $path = secretFile("GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n");

        (new Scanner(app(Redactor::class)))->scanFile($path, 'file_scan');

        expect(SpyVerifier::$seen)->toBe([]);

        cleanupDirectory(dirname($path));
    });
});

describe('Verification changes triage', function () {
    afterEach(fn () => SpyVerifier::$seen = []);

    it('ranks a confirmed-live credential above everything else', function () {
        $path = secretFile("GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n");

        $scanner = (new Scanner(app(Redactor::class)))
            ->withVerifier(new SecretVerifier(['spy'], [new SpyVerifier(VerificationStatus::Active)]));

        $finding = $scanner->scanFile($path, 'file_scan')->findings[0];

        expect($finding->severity())->toBe('critical')
            ->and($finding->verification?->status)->toBe(VerificationStatus::Active);

        cleanupDirectory(dirname($path));
    });

    it('does not downgrade an unverifiable finding to safe', function () {
        // A check that could not complete is not evidence of safety.
        expect(VerificationStatus::Unknown->severity())->toBe('high')
            ->and(VerificationStatus::Inactive->severity())->toBe('low')
            ->and(VerificationStatus::Active->severity())->toBe('critical');
    });

    it('reports the verdict in JSON output', function () {
        $path = secretFile("GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n");

        $scanner = (new Scanner(app(Redactor::class)))
            ->withVerifier(new SecretVerifier(['spy'], [new SpyVerifier(VerificationStatus::Inactive)]));

        $finding = $scanner->scanFile($path, 'file_scan')->findings[0]->toArray();

        expect($finding['verification']['status'])->toBe('inactive')
            ->and($finding['verification']['verifier'])->toBe('spy');

        cleanupDirectory(dirname($path));
    });
});

describe('Built-in verifiers', function () {
    it('reads GitHub 401 as inactive', function () {
        Http::fake(['api.github.com/*' => Http::response([], 401)]);

        expect((new GitHubTokenVerifier)->verify('ghp_x')->status)->toBe(VerificationStatus::Inactive);
    });

    it('reads GitHub 200 as live', function () {
        Http::fake(['api.github.com/*' => Http::response(['login' => 'someone'], 200)]);

        expect((new GitHubTokenVerifier)->verify('ghp_x')->status)->toBe(VerificationStatus::Active);
    });

    it('reads an unexpected GitHub status as unknown', function () {
        Http::fake(['api.github.com/*' => Http::response([], 503)]);

        expect((new GitHubTokenVerifier)->verify('ghp_x')->status)->toBe(VerificationStatus::Unknown);
    });

    it('reads Stripe 401 as inactive', function () {
        Http::fake(['api.stripe.com/*' => Http::response([], 401)]);

        expect((new StripeKeyVerifier)->verify('sk_live_x')->status)->toBe(VerificationStatus::Inactive);
    });

    it('reads Stripe 200 as live', function () {
        Http::fake(['api.stripe.com/*' => Http::response(['object' => 'balance'], 200)]);

        expect((new StripeKeyVerifier)->verify('sk_live_x')->status)->toBe(VerificationStatus::Active);
    });

    it('reads a Slack rejection from the body, not the status code', function () {
        // Slack answers 200 either way; trusting the status alone would call
        // every dead token live.
        Http::fake(['slack.com/*' => Http::response(['ok' => false, 'error' => 'invalid_auth'], 200)]);

        $result = (new SlackTokenVerifier)->verify('xoxb-x');

        expect($result->status)->toBe(VerificationStatus::Inactive)
            ->and($result->note)->toContain('invalid_auth');
    });

    it('reads a Slack acceptance from the body', function () {
        Http::fake(['slack.com/*' => Http::response(['ok' => true, 'team' => 'acme'], 200)]);

        expect((new SlackTokenVerifier)->verify('xoxb-x')->status)->toBe(VerificationStatus::Active);
    });

    it('never lets a transport failure escape as an exception', function () {
        Http::fake(fn () => throw new \RuntimeException('connection refused'));

        expect((new GitHubTokenVerifier)->verify('ghp_x')->status)->toBe(VerificationStatus::Unknown)
            ->and((new StripeKeyVerifier)->verify('sk_x')->status)->toBe(VerificationStatus::Unknown)
            ->and((new SlackTokenVerifier)->verify('xoxb-x')->status)->toBe(VerificationStatus::Unknown);
    });

    it('routes each entity to the right verifier', function () {
        expect((new GitHubTokenVerifier)->supports('github_token', 'x'))->toBeTrue()
            ->and((new GitHubTokenVerifier)->supports('stripe_key', 'x'))->toBeFalse()
            ->and((new StripeKeyVerifier)->supports('x', 'api_key_stripe'))->toBeTrue()
            ->and((new SlackTokenVerifier)->supports('slack_token', 'x'))->toBeTrue();
    });
});

describe('The scan command gate', function () {
    beforeEach(function () {
        config(['redactor.scan.profile' => 'file_scan', 'redactor.scan.baseline' => null]);
        $this->path = secretFile("GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n");
    });

    afterEach(fn () => cleanupDirectory(dirname($this->path)));

    it('refuses --verify when config has not enabled it', function () {
        config(['redactor.scan.verification' => ['enabled' => false, 'verifiers' => ['github_token']]]);

        $exit = Artisan::call('redactor:scan', ['paths' => [$this->path], '--verify' => true]);

        expect($exit)->toBe(1)
            ->and(Artisan::output())->toContain('Verification is not enabled');
    });

    it('refuses --verify when enabled with an empty allowlist', function () {
        config(['redactor.scan.verification' => ['enabled' => true, 'verifiers' => []]]);

        expect(Artisan::call('redactor:scan', ['paths' => [$this->path], '--verify' => true]))->toBe(1);
    });

    it('names the hosts before contacting any of them', function () {
        config(['redactor.scan.verification' => ['enabled' => true, 'verifiers' => ['github_token']]]);
        Http::fake(['api.github.com/*' => Http::response([], 401)]);

        Artisan::call('redactor:scan', ['paths' => [$this->path], '--verify' => true]);

        expect(Artisan::output())->toContain('api.github.com');
    });

    it('sends nothing when --verify is absent, however config is set', function () {
        config(['redactor.scan.verification' => ['enabled' => true, 'verifiers' => ['github_token']]]);
        Http::fake();

        Artisan::call('redactor:scan', ['paths' => [$this->path]]);

        Http::assertNothingSent();
    });
});
