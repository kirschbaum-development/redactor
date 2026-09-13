<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Strategies\BlockedKeysStrategy;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;

function blockedKeyProfile(array $overrides = []): array
{
    return array_merge([
        'enabled' => true,
        'strategies' => [BlockedKeysStrategy::class, RegexPatternsStrategy::class],
        'safe_keys' => [],
        'blocked_keys' => [],
        'patterns' => [
            'email' => ['pattern' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/', 'entity' => 'email'],
        ],
        'operators' => ['default' => 'redact'],
        'min_confidence' => 0.0,
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

describe('Blocked keys go through operators', function (): void {
    it('applies the entity operator to a value found by its key', function (): void {
        config()->set('redactor.profiles.blocked', blockedKeyProfile([
            'blocked_keys' => ['email'],
            'operators' => ['default' => 'redact', 'email' => ['surrogate' => ['preserve_domain' => true]]],
        ]));

        $result = resolve(Redactor::class)->redact(['email' => 'alice@customer.com'], 'blocked');

        expect($result['email'])->toMatch('/^u_[a-z0-9]+@customer\.com$/');
    });

    it('produces the same surrogate whether the key or the pattern found it', function (): void {
        config()->set('redactor.profiles.blocked', blockedKeyProfile([
            'blocked_keys' => ['email'],
            'operators' => ['default' => 'redact', 'email' => 'surrogate'],
        ]));

        $result = resolve(Redactor::class)->redact([
            'email' => 'alice@customer.com',
            'note' => 'from alice@customer.com',
        ], 'blocked');

        expect($result['note'])->toBe('from '.$result['email']);
    });

    it('still collapses a container under a blocked key to the replacement', function (): void {
        config()->set('redactor.profiles.blocked', blockedKeyProfile([
            'blocked_keys' => ['credentials'],
            'operators' => ['default' => 'hash'],
        ]));

        $result = resolve(Redactor::class)->redact(['credentials' => ['user' => 'a', 'pass' => 'b']], 'blocked');

        expect($result['credentials'])->toBe('[REDACTED]');
    });

    it('reports the key finding with a certain score', function (): void {
        config()->set('redactor.profiles.blocked', blockedKeyProfile(['blocked_keys' => ['password']]));

        $result = resolve(Redactor::class)->inspect(['password' => 'hunter2'], 'blocked');

        expect($result->findings[0]->rule)->toBe('blocked_key')
            ->and($result->findings[0]->confidence?->score)->toBe(1.0);
    });
});
