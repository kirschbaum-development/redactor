<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Strategies\KnownSecretsStrategy;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;
use Kirschbaum\Redactor\Support\SecretRegistry;

function knownSecretsProfile(array $overrides = []): array
{
    return array_merge([
        'enabled' => true,
        'strategies' => [KnownSecretsStrategy::class, RegexPatternsStrategy::class],
        'safe_keys' => [],
        'blocked_keys' => [],
        'patterns' => [],
        'known_secrets' => ['values' => ['s3cr3t-value-1'], 'config' => []],
        'operators' => ['default' => 'redact'],
        'replacement' => '[REDACTED]',
        'mark_redacted' => false,
        'track_redacted_keys' => false,
        'non_redactable_object_behavior' => 'preserve',
        'max_value_length' => null,
        'redact_large_objects' => false,
        'max_object_size' => 100,
        'pseudonymization' => ['key' => testPseudonymizationKey()],
        'shannon_entropy' => ['enabled' => false],
    ], $overrides);
}

describe('Known secrets', function (): void {
    beforeEach(fn () => config()->set('redactor.profiles.known', knownSecretsProfile()));

    it('redacts a configured value wherever it appears verbatim', function (): void {
        $result = resolve(Redactor::class)->redact([
            'msg' => 'called with s3cr3t-value-1 twice: s3cr3t-value-1',
            'json' => '{"token":"s3cr3t-value-1"}',
        ], 'known');

        expect($result['msg'])->toBe('called with [REDACTED] twice: [REDACTED]')
            ->and($result['json'])->toBe('{"token":"[REDACTED]"}');
    });

    it('is case-sensitive, because secrets are', function (): void {
        expect(resolve(Redactor::class)->redact('S3CR3T-VALUE-1', 'known'))->toBe('S3CR3T-VALUE-1');
    });

    it('reads secrets from config keys, including every string under an array', function (): void {
        config()->set('services.acme', ['key' => 'acme-key-12345', 'secret' => 'acme-secret-67890', 'enabled' => true, 'retries' => 3]);
        config()->set('redactor.profiles.known.known_secrets', ['config' => ['services.acme', 'app.missing']]);

        expect(resolve(Redactor::class)->redact('acme-key-12345 / acme-secret-67890', 'known'))
            ->toBe('[REDACTED] / [REDACTED]');
    });

    it('refuses values too short to match safely', function (): void {
        $registry = new SecretRegistry;

        expect($registry->add('short'))->toBeFalse()
            ->and($registry->add('long-enough'))->toBeTrue()
            ->and($registry->count())->toBe(1);
    });

    it('accepts secrets registered at runtime, for every profile', function (): void {
        $redactor = resolve(Redactor::class);
        $redactor->registerSecret('minted-at-runtime-token');

        expect($redactor->redact('using minted-at-runtime-token now', 'known'))
            ->toBe('using [REDACTED] now');
    });

    it('goes through the operator for its entity', function (): void {
        config()->set('redactor.profiles.known.operators', ['default' => 'redact', 'known_secret' => 'hash']);

        expect(resolve(Redactor::class)->redact('x s3cr3t-value-1 y', 'known'))
            ->toMatch('/^x \[known_secret:[a-z0-9]+\] y$/');
    });

    it('reports the finding as certain', function (): void {
        $result = resolve(Redactor::class)->inspect('s3cr3t-value-1', 'known');

        expect($result->findings[0]->rule)->toBe('known_secret')
            ->and($result->findings[0]->confidence?->score)->toBe(1.0);
    });

    it('redacts APP_KEY in the shipped default profile', function (): void {
        $key = 'base64:'.base64_encode(random_bytes(32));
        config()->set('app.key', $key);

        $result = resolve(Redactor::class)->redact(['note' => "leaked {$key} here"]);

        expect($result['note'])->not->toContain($key)
            ->and($result['note'])->toStartWith('leaked ');
    });

    it('does not fail the profile when a configured secret is null', function (): void {
        config()->set('redactor.profiles.known.known_secrets', ['config' => ['services.nothing.key']]);

        expect(resolve(Redactor::class)->redact('fine', 'known'))->toBe('fine');
    });
});
