<?php

declare(strict_types=1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Log;
use Kirschbaum\Redactor\Logging\ReadactFormatter;
use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Strategies\BlockedKeysStrategy;
use Kirschbaum\Redactor\Strategies\RedactionStrategyInterface;
use Kirschbaum\Redactor\Support\InternalLog;
use Monolog\DateTimeImmutable;
use Monolog\Level;
use Monolog\LogRecord;

/**
 * A strategy that fails on the exact value it is meant to protect.
 */
class ExplodingStrategy implements RedactionStrategyInterface
{
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        return $key === 'password';
    }

    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        throw new \RuntimeException('strategy blew up');
    }
}

function record(string $message, array $context = []): LogRecord
{
    return new LogRecord(
        new DateTimeImmutable(true),
        'testing',
        Level::Info,
        $message,
        $context,
        []
    );
}

describe('Fail-safe redaction', function () {
    it('throws from redact() so direct callers learn about a bad profile', function () {
        expect(fn () => app(Redactor::class)->redact(['a' => 1], 'does_not_exist'))
            ->toThrow(\InvalidArgumentException::class, "Redaction profile 'does_not_exist' not found");
    });

    it('does not throw from redactSafely() for an unknown profile', function () {
        $result = app(Redactor::class)->redactSafely(['secret' => 'value'], 'does_not_exist');

        expect($result)->toBe('[REDACTED] (redaction failed)');
    });

    it('replaces rather than passes through when redaction fails', function () {
        // The whole point: a failure must not emit the payload it could not
        // verify as safe.
        $result = app(Redactor::class)->redactSafely(
            ['password' => 'hunter2', 'card' => '4111111111111111'],
            'does_not_exist'
        );

        expect($result)->toBeString()
            ->and($result)->not->toContain('hunter2')
            ->and($result)->not->toContain('4111111111111111');
    });

    it('survives a strategy that throws mid-redaction', function () {
        config()->set('redactor.custom_strategies', ['exploding' => ExplodingStrategy::class]);
        config()->set('redactor.profiles.exploding', [
            'enabled' => true,
            'strategies' => ['exploding'],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => false,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => ['enabled' => false],
        ]);

        $result = app(Redactor::class)->redactSafely(['password' => 'hunter2'], 'exploding');

        expect($result)->toBe('[REDACTED] (redaction failed)')
            ->and($result)->not->toContain('hunter2');
    });

    it('uses the profile replacement string in the failure marker when it can', function () {
        config()->set('redactor.custom_strategies', ['exploding' => ExplodingStrategy::class]);
        config()->set('redactor.profiles.exploding_masked', [
            'enabled' => true,
            'strategies' => ['exploding'],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '***',
            'mark_redacted' => false,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => ['enabled' => false],
        ]);

        expect(app(Redactor::class)->redactSafely(['password' => 'x'], 'exploding_masked'))
            ->toBe('*** (redaction failed)');
    });

    it('keeps the log channel alive when the configured profile is broken', function () {
        config()->set('redactor.default_profile', 'missing_profile');

        $formatter = new ReadactFormatter;

        // Previously this propagated InvalidArgumentException out of Monolog and
        // killed every subsequent write to the channel.
        $output = $formatter->format(record('user bob@example.com signed in', ['password' => 'hunter2']));

        expect($output)->toBeString()
            ->and($output)->toContain('testing.INFO')
            ->and($output)->not->toContain('hunter2')
            ->and($output)->not->toContain('bob@example.com');
    });

    it('does not re-enter the logger while reporting its own failure', function () {
        expect(InternalLog::isEmitting())->toBeFalse();

        $seen = [];

        // A logger that calls back into redaction is exactly the re-entrancy
        // that used to loop until the stack ran out.
        Log::listen(function ($message) use (&$seen) {
            $seen[] = $message->message;
            InternalLog::warning('nested diagnostic');
        });

        app(Redactor::class)->redactSafely(['a' => 1], 'does_not_exist');

        expect($seen)->toHaveCount(1)
            ->and(InternalLog::isEmitting())->toBeFalse();
    });

    it('swallows a logger that throws while reporting a failure', function () {
        Log::listen(function () {
            throw new \RuntimeException('logger is down');
        });

        $result = app(Redactor::class)->redactSafely(['a' => 1], 'does_not_exist');

        expect($result)->toBe('[REDACTED] (redaction failed)');
    });
});

describe('redactor:validate', function () {
    it('passes when every profile resolves', function () {
        $this->artisan('redactor:validate')
            ->assertSuccessful();
    });

    it('fails and names a profile whose config is invalid', function () {
        config()->set('redactor.profiles.broken', [
            'enabled' => true,
            'strategies' => [BlockedKeysStrategy::class],
            'max_object_size' => 'lots',
            'shannon_entropy' => ['enabled' => false],
        ]);

        $this->artisan('redactor:validate')
            ->expectsOutputToContain('broken')
            ->assertFailed();
    });

    it('fails when a profile lists a strategy that cannot be resolved', function () {
        config()->set('redactor.profiles.ghost', [
            'enabled' => true,
            'strategies' => ['App\\Nope\\NotARealStrategy'],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => false,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => ['enabled' => false],
        ]);

        $this->artisan('redactor:validate')
            ->expectsOutputToContain('ghost')
            ->assertFailed();
    });

    it('reports no profiles as a failure rather than a pass', function () {
        config()->set('redactor.profiles', []);

        $this->artisan('redactor:validate')->assertFailed();
    });
});
