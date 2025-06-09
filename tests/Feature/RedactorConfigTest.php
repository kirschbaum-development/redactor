<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\RedactorConfig;

describe('Redactor Configuration Tests', function () {
    beforeEach(function () {
        // Set up basic profile structure for tests
        config()->set('redactor.default_profile', 'default');
    });

    it('can be disabled via configuration', function () {
        config()->set('redactor.profiles.default', [
            'enabled' => false,
            'strategies' => [\Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class],
            'safe_keys' => [],
            'blocked_keys' => ['password'],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => true,
            'max_object_size' => 100,
            'shannon_entropy' => ['enabled' => false],
        ]);

        $redactor = new Redactor;

        $context = [
            'password' => 'secret123',
            'email' => 'user@example.com',
        ];

        $result = $redactor->redact($context);

        expect($result)->toBe($context);
    });

    it('does not add redacted flag when mark_redacted is false', function () {
        config()->set('redactor.profiles.default', [
            'enabled' => true,
            'strategies' => [\Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class],
            'safe_keys' => [],
            'blocked_keys' => ['password'],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => false,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => true,
            'max_object_size' => 100,
            'shannon_entropy' => ['enabled' => false],
        ]);

        $redactor = new Redactor;

        $context = ['password' => 'secret123'];
        $result = $redactor->redact($context);

        expect($result['password'])->toBe('[REDACTED]')
            ->and($result)->not->toHaveKey('_redacted');
    });
});

describe('RedactorConfig DTO Tests', function () {
    beforeEach(function () {
        config()->set('redactor.default_profile', 'default');
    });

    it('creates config from Laravel configuration with defaults', function () {
        config()->set('redactor.profiles.default', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => true,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.8,
                'min_length' => 25,
                'exclusion_patterns' => [],
            ],
        ]);

        $config = RedactorConfig::fromConfig();

        expect($config->safeKeys)->toBe([])
            ->and($config->blockedKeys)->toBe([])
            ->and($config->patterns)->toBe([])
            ->and($config->replacement)->toBe('[REDACTED]')
            ->and($config->maxValueLength)->toBeNull()
            ->and($config->redactLargeObjects)->toBeTrue()
            ->and($config->maxObjectSize)->toBe(100)
            ->and($config->shannonEntropy['enabled'])->toBeTrue()
            ->and($config->shannonEntropy['threshold'])->toBe(4.8)
            ->and($config->shannonEntropy['min_length'])->toBe(25)
            ->and($config->markRedacted)->toBeTrue()
            ->and($config->trackRedactedKeys)->toBeFalse()
            ->and($config->nonRedactableObjectBehavior)->toBe('preserve')
            ->and($config->profile)->toBe('default');
    });

    it('creates config with custom values and handles invalid patterns', function () {
        config()->set('redactor.profiles.default', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
            ],
            'safe_keys' => ['ID', 'User_ID'],
            'blocked_keys' => ['PASSWORD', 'Secret'],
            'patterns' => [
                'valid' => '/valid-pattern/',
                'invalid' => '(invalid-pattern', // Invalid regex
                'another_valid' => '/another-valid-pattern/',
            ],
            'replacement' => '[CUSTOM]',
            'mark_redacted' => true,
            'track_redacted_keys' => true,
            'non_redactable_object_behavior' => 'remove',
            'max_value_length' => 100,
            'redact_large_objects' => true,
            'max_object_size' => 100,
            'shannon_entropy' => ['enabled' => false],
        ]);

        $config = RedactorConfig::fromConfig();

        expect($config->safeKeys)->toBe(['id', 'user_id']) // Converted to lowercase
            ->and($config->blockedKeys)->toBe(['password', 'secret']) // Converted to lowercase
            ->and($config->patterns)->toBe(['valid' => '/valid-pattern/', 'another_valid' => '/another-valid-pattern/']) // Invalid pattern filtered out
            ->and($config->replacement)->toBe('[CUSTOM]')
            ->and($config->maxValueLength)->toBe(100)
            ->and($config->trackRedactedKeys)->toBeTrue()
            ->and($config->nonRedactableObjectBehavior)->toBe('remove');
    });

    it('handles non-integer max_value_length config', function () {
        config()->set('redactor.profiles.default', [
            'enabled' => true,
            'strategies' => [\Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => 'not_an_integer',
            'redact_large_objects' => true,
            'max_object_size' => 100,
            'shannon_entropy' => ['enabled' => false],
        ]);

        $config = RedactorConfig::fromConfig();

        expect($config->maxValueLength)->toBeNull();
    });

    it('throws exception for non-existent profile', function () {
        config()->set('redactor.profiles', []); // Empty profiles

        expect(fn () => RedactorConfig::fromConfig('non_existent'))
            ->toThrow(\InvalidArgumentException::class, "Redaction profile 'non_existent' not found in configuration.");
    });

    it('can list available profiles', function () {
        config()->set('redactor.profiles', [
            'default' => ['enabled' => true],
            'strict' => ['enabled' => true],
            'performance' => ['enabled' => true],
        ]);

        $profiles = RedactorConfig::getAvailableProfiles();

        expect($profiles)->toBeArray()
            ->and($profiles)->toContain('default')
            ->and($profiles)->toContain('strict')
            ->and($profiles)->toContain('performance')
            ->and($profiles)->toHaveCount(3);
    });

    it('checks if profile exists', function () {
        config()->set('redactor.profiles', [
            'default' => ['enabled' => true],
            'strict' => ['enabled' => true],
        ]);

        expect(RedactorConfig::profileExists('default'))->toBeTrue()
            ->and(RedactorConfig::profileExists('strict'))->toBeTrue()
            ->and(RedactorConfig::profileExists('non_existent'))->toBeFalse();
    });

    it('throws exception for invalid profile configuration types', function () {
        // Test when profile config is not an array
        config()->set('redactor.profiles.invalid_profile', 'not_an_array');

        expect(function () {
            RedactorConfig::fromConfig('invalid_profile');
        })->toThrow(\InvalidArgumentException::class, "Invalid configuration for profile 'invalid_profile'");
    });

    it('handles zero and negative values in max value length validation', function () {
        // Test validateMaxValueLength returning null for zero/negative values
        config()->set('redactor.profiles.test_zero_max', [
            'enabled' => true,
            'strategies' => [],
            'max_value_length' => 0, // Zero value should return null
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'redact_large_objects' => true,
            'max_object_size' => 100,
            'shannon_entropy' => ['enabled' => false],
        ]);

        $config = RedactorConfig::fromConfig('test_zero_max');
        expect($config->maxValueLength)->toBeNull();

        // Test with negative value
        config()->set('redactor.profiles.test_negative_max', [
            'enabled' => true,
            'strategies' => [],
            'max_value_length' => -5, // Negative value should return null
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'redact_large_objects' => true,
            'max_object_size' => 100,
            'shannon_entropy' => ['enabled' => false],
        ]);

        $config2 = RedactorConfig::fromConfig('test_negative_max');
        expect($config2->maxValueLength)->toBeNull();
    });

    it('validates regex patterns and removes invalid ones', function () {
        // Test validatePatterns with invalid regex patterns
        config()->set('redactor.profiles.test_invalid_patterns', [
            'enabled' => true,
            'strategies' => [],
            'patterns' => [
                'valid_pattern' => '/test/',
                'invalid_pattern' => '[invalid regex', // Invalid regex
                'non_string_pattern' => 123, // Non-string pattern
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => true,
            'max_object_size' => 100,
            'shannon_entropy' => ['enabled' => false],
        ]);

        $config = RedactorConfig::fromConfig('test_invalid_patterns');

        // Should only have the valid pattern
        expect($config->patterns)->toHaveCount(1);
        expect($config->patterns)->toHaveKey('valid_pattern');
    });
});
