<?php

declare(strict_types=1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Http;
use Kirschbaum\Redactor\Verification\SecretVerifier;
use Kirschbaum\Redactor\Verification\VerificationResult;
use Kirschbaum\Redactor\Verification\VerificationStatus;
use Kirschbaum\Redactor\Verification\Verifier;
use Kirschbaum\Redactor\Verification\Verifiers\AnthropicKeyVerifier;
use Kirschbaum\Redactor\Verification\Verifiers\GoogleApiKeyVerifier;
use Kirschbaum\Redactor\Verification\Verifiers\OpenAiKeyVerifier;
use Kirschbaum\Redactor\Verification\Verifiers\SendGridKeyVerifier;

describe('Provider verifiers', function (): void {
    it('classify OpenAI answers', function (): void {
        $verifier = new OpenAiKeyVerifier;

        Http::fake(['api.openai.com/*' => Http::sequence()->push(['data' => []], 200)->push([], 401)->push([], 503)]);

        expect($verifier->verify('sk-x')->status)->toBe(VerificationStatus::Active)
            ->and($verifier->verify('sk-x')->status)->toBe(VerificationStatus::Inactive)
            ->and($verifier->verify('sk-x')->status)->toBe(VerificationStatus::Unknown);

        expect($verifier->supports('openai_key', 'x'))->toBeTrue()
            ->and($verifier->supports('other', 'my_openai_rule'))->toBeTrue()
            ->and($verifier->supports('other', 'x'))->toBeFalse()
            ->and($verifier->host())->toBe('api.openai.com');
    });

    it('classify Anthropic answers and send the version header', function (): void {
        $verifier = new AnthropicKeyVerifier;

        Http::fake(['api.anthropic.com/*' => Http::sequence()->push(['data' => []], 200)->push([], 401)->push([], 529)]);

        expect($verifier->verify('sk-ant-x')->status)->toBe(VerificationStatus::Active)
            ->and($verifier->verify('sk-ant-x')->status)->toBe(VerificationStatus::Inactive)
            ->and($verifier->verify('sk-ant-x')->status)->toBe(VerificationStatus::Unknown);

        Http::assertSent(fn ($request): bool => $request->hasHeader('x-api-key', 'sk-ant-x') && $request->hasHeader('anthropic-version'));

        expect($verifier->name())->toBe('anthropic_key')
            ->and($verifier->supports('anthropic_key', 'x'))->toBeTrue();
    });

    it('classify SendGrid answers', function (): void {
        $verifier = new SendGridKeyVerifier;

        Http::fake(['api.sendgrid.com/*' => Http::sequence()->push(['scopes' => []], 200)->push([], 403)->push([], 401)->push([], 500)]);

        expect($verifier->verify('SG.x')->status)->toBe(VerificationStatus::Active)
            ->and($verifier->verify('SG.x')->status)->toBe(VerificationStatus::Inactive)
            ->and($verifier->verify('SG.x')->status)->toBe(VerificationStatus::Inactive)
            ->and($verifier->verify('SG.x')->status)->toBe(VerificationStatus::Unknown);

        expect($verifier->name())->toBe('sendgrid_key')
            ->and($verifier->supports('sendgrid_key', 'x'))->toBeTrue();
    });

    it('classify Google answers, treating a disabled-API 403 as live', function (): void {
        $verifier = new GoogleApiKeyVerifier;

        Http::fake(['generativelanguage.googleapis.com/*' => Http::sequence()
            ->push(['models' => []], 200)
            ->push([], 403)
            ->push(['error' => 'API key not valid'], 400)
            ->push([], 502)]);

        expect($verifier->verify('AIzaX')->status)->toBe(VerificationStatus::Active)
            ->and($verifier->verify('AIzaX')->status)->toBe(VerificationStatus::Active)
            ->and($verifier->verify('AIzaX')->status)->toBe(VerificationStatus::Inactive)
            ->and($verifier->verify('AIzaX')->status)->toBe(VerificationStatus::Unknown);

        Http::assertSent(fn ($request): bool => str_contains($request->url(), 'key=AIzaX'));

        expect($verifier->name())->toBe('google_api_key')
            ->and($verifier->supports('google_api_key', 'x'))->toBeTrue();
    });

    it('report an unreachable provider as unknown', function (): void {
        Http::fake(fn () => throw new \RuntimeException('dns'));

        foreach ([new OpenAiKeyVerifier, new AnthropicKeyVerifier, new SendGridKeyVerifier, new GoogleApiKeyVerifier] as $verifier) {
            expect($verifier->verify('x')->status)->toBe(VerificationStatus::Unknown);
        }
    });

    it('are all shipped and allow-listable by name, alongside registered ones', function (): void {
        SecretVerifier::register(new class implements Verifier
        {
            public function name(): string
            {
                return 'acme';
            }

            public function host(): string
            {
                return 'acme.test';
            }

            public function supports(string $entity, string $rule): bool
            {
                return $entity === 'acme_key';
            }

            public function verify(string $secret): VerificationResult
            {
                return VerificationResult::active();
            }
        });

        $verifier = new SecretVerifier(['openai_key', 'anthropic_key', 'sendgrid_key', 'google_api_key', 'acme']);

        expect($verifier->hosts())->toBe(['acme.test', 'api.anthropic.com', 'api.openai.com', 'api.sendgrid.com', 'generativelanguage.googleapis.com'])
            ->and($verifier->canVerify('acme_key', 'x'))->toBeTrue()
            ->and($verifier->verify('acme_key', 'x', 's')->status)->toBe(VerificationStatus::Active);
    });
});
