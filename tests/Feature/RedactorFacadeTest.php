<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Facades\Redactor;

describe('Redactor Facade Tests', function () {
    beforeEach(function () {
        // Set up basic profile for facade testing
        config()->set('redactor.default_profile', 'facade_test');
        config()->set('redactor.profiles.facade_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
            ],
            'safe_keys' => ['id'],
            'blocked_keys' => ['password'],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => ['enabled' => false],
        ]);
    });

    test('facade can redact data using default profile', function () {
        $data = [
            'id' => 123,
            'password' => 'secret123',
        ];

        $result = Redactor::redact($data);

        expect($result['id'])->toBe(123)
            ->and($result['password'])->toBe('[REDACTED]')
            ->and($result['_redacted'])->toBeTrue();
    });

    test('facade can redact data using specific profile', function () {
        // Set up a different profile
        config()->set('redactor.profiles.strict_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => ['id', 'password'],
            'patterns' => [],
            'replacement' => '[STRICT_REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => ['enabled' => false],
        ]);

        $data = [
            'id' => 123,
            'password' => 'secret123',
        ];

        $result = Redactor::redact($data, 'strict_test');

        expect($result['id'])->toBe('[STRICT_REDACTED]')
            ->and($result['password'])->toBe('[STRICT_REDACTED]')
            ->and($result['_redacted'])->toBeTrue();
    });

    test('facade can get available profiles', function () {
        $profiles = Redactor::getAvailableProfiles();

        expect($profiles)->toBeArray()
            ->and($profiles)->toContain('facade_test');
    });

    test('facade can check if profile exists', function () {
        expect(Redactor::profileExists('facade_test'))->toBeTrue()
            ->and(Redactor::profileExists('non_existent'))->toBeFalse();
    });

    test('facade provides fresh instances to avoid state conflicts', function () {
        // This test ensures that multiple facade calls don't interfere with each other
        $data1 = ['id' => 1, 'password' => 'secret1'];
        $data2 = ['id' => 2, 'password' => 'secret2'];

        // These should work independently without state conflicts
        $result1 = Redactor::redact($data1);
        $result2 = Redactor::redact($data2);

        expect($result1['password'])->toBe('[REDACTED]')
            ->and($result2['password'])->toBe('[REDACTED]')
            ->and($result1['id'])->toBe(1) // Different IDs prove they're separate
            ->and($result2['id'])->toBe(2)
            ->and($result1['_redacted'])->toBeTrue()
            ->and($result2['_redacted'])->toBeTrue();
    });
});
