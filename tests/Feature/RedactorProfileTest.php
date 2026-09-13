<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Exceptions\ProfileNotFoundException;
use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Strategies\BlockedKeysStrategy;
use Kirschbaum\Redactor\Strategies\Contracts\Strategy;
use Kirschbaum\Redactor\Strategies\SafeKeysStrategy;

describe('Redactor Profile Tests', function (): void {
    beforeEach(function (): void {
        // Set up the profile-based config structure
        config()->set('redactor.default_profile', 'default');
        config()->set('redactor.profiles', [
            'default' => [
                'enabled' => true,
                'strategies' => [
                    SafeKeysStrategy::class,
                    BlockedKeysStrategy::class,
                ],
                'safe_keys' => ['id', 'uuid'],
                'blocked_keys' => ['password', 'secret'],
                'patterns' => [
                    'email' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/',
                ],
                'replacement' => '[REDACTED]',
                'mark_redacted' => true,
                'track_redacted_keys' => false,
                'non_redactable_object_behavior' => 'preserve',
                'max_value_length' => 5000,
                'redact_large_objects' => true,
                'max_object_size' => 100,
                'shannon_entropy' => [
                    'enabled' => false,
                ],
            ],
            'strict' => [
                'enabled' => true,
                'strategies' => [
                    SafeKeysStrategy::class,
                    BlockedKeysStrategy::class,
                ],
                'safe_keys' => ['id'],
                'blocked_keys' => ['password', 'secret', 'email', 'name'],
                'patterns' => [],
                'replacement' => '[STRICT_REDACTED]',
                'mark_redacted' => true,
                'track_redacted_keys' => true,
                'non_redactable_object_behavior' => 'redact',
                'max_value_length' => 1000,
                'redact_large_objects' => true,
                'max_object_size' => 25,
                'shannon_entropy' => [
                    'enabled' => false,
                ],
            ],
            'performance' => [
                'enabled' => true,
                'strategies' => [
                    SafeKeysStrategy::class,
                    BlockedKeysStrategy::class,
                    // No large object or string strategies for performance
                ],
                'safe_keys' => ['id', 'uuid', 'timestamp', 'level'],
                'blocked_keys' => ['password', 'secret'],
                'patterns' => [],
                'replacement' => '[REDACTED]',
                'mark_redacted' => false, // Disabled for performance
                'track_redacted_keys' => false,
                'non_redactable_object_behavior' => 'preserve',
                'max_value_length' => null,
                'redact_large_objects' => false,
                'max_object_size' => null,
                'shannon_entropy' => [
                    'enabled' => false,
                ],
            ],
        ]);
    });

    test('it uses the default profile when no profile is specified', function (): void {
        $redactor = new Redactor;

        $data = [
            'id' => 123,
            'password' => 'secret123',
            'name' => 'John Doe',
        ];

        $result = $redactor->redact($data);

        expect($result['id'])->toBe(123) // safe key
            ->and($result['password'])->toBe('[REDACTED]') // blocked key
            ->and($result['name'])->toBe('John Doe') // not in blocked keys for default profile
            ->and($result['_redacted'])->toBeTrue();
    });

    test('it uses the specified profile when provided', function (): void {
        $redactor = new Redactor;

        $data = [
            'id' => 123,
            'password' => 'secret123',
            'name' => 'John Doe',
        ];

        $result = $redactor->redact($data, 'strict');

        expect($result['id'])->toBe(123) // safe key
            ->and($result['password'])->toBe('[STRICT_REDACTED]') // blocked key
            ->and($result['name'])->toBe('[STRICT_REDACTED]') // blocked in strict profile
            ->and($result['_redacted'])->toBeTrue()
            ->and($result['_redacted_keys'])->toBeArray() // track_redacted_keys enabled in strict
            ->and($result['_redacted_keys'])->toContain('password')
            ->and($result['_redacted_keys'])->toContain('name');
    });

    test('it respects profile-specific configuration options', function (): void {
        $redactor = new Redactor;

        $data = [
            'password' => 'secret123',
            'user' => 'john',
        ];

        // Performance profile has mark_redacted disabled
        $result = $redactor->redact($data, 'performance');

        expect($result['password'])->toBe('[REDACTED]')
            ->and($result['user'])->toBe('john')
            ->and($result)->not->toHaveKey('_redacted'); // No redaction metadata
    });

    test('it throws exception for non-existent profile', function (): void {
        $redactor = new Redactor;

        expect(fn (): mixed => $redactor->redact(['test' => 'data'], 'non_existent'))
            ->toThrow(ProfileNotFoundException::class, 'Redaction profile [non_existent] is not configured.');
    });

    test('it can list available profiles', function (): void {
        $redactor = new Redactor;

        $profiles = $redactor->profiles();

        expect($profiles)->toBeArray()
            ->and($profiles)->toContain('default')
            ->and($profiles)->toContain('strict')
            ->and($profiles)->toContain('performance')
            ->and($profiles)->toHaveCount(3);
    });

    test('it can check if a profile exists', function (): void {
        $redactor = new Redactor;

        expect($redactor->hasProfile('default'))->toBeTrue()
            ->and($redactor->hasProfile('strict'))->toBeTrue()
            ->and($redactor->hasProfile('performance'))->toBeTrue()
            ->and($redactor->hasProfile('non_existent'))->toBeFalse();
    });

    test('it loads strategies based on profile configuration', function (): void {
        $redactor = new Redactor;

        $defaultStrategies = $redactor->strategies('default');
        $performanceStrategies = $redactor->strategies('performance');

        expect($defaultStrategies)->toBeArray()
            ->and($performanceStrategies)->toBeArray();

        // Both should have safe_keys and blocked_keys
        $defaultStrategyNames = array_map(get_class(...), $defaultStrategies);
        $performanceStrategyNames = array_map(get_class(...), $performanceStrategies);

        expect($defaultStrategyNames)->toContain(SafeKeysStrategy::class)
            ->and($defaultStrategyNames)->toContain(BlockedKeysStrategy::class)
            ->and($performanceStrategyNames)->toContain(SafeKeysStrategy::class)
            ->and($performanceStrategyNames)->toContain(BlockedKeysStrategy::class);
    });

    test('it can register custom strategies', function (): void {
        $redactor = new Redactor;

        $customStrategy = new class implements Strategy
        {
            public function getPriority(): int
            {
                return 10;
            }

            public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
            {
                return $key === 'custom_field';
            }

            public function handle(mixed $value, string $key, RedactionContext $context): mixed
            {
                $context->markRedacted();

                return '[CUSTOM_REDACTED]';
            }
        };

        $redactor->registerCustomStrategy('my_custom', $customStrategy);

        // Test that we can get strategies (should include our custom one for profiles that use it)
        $strategies = $redactor->strategies();
        expect($strategies)->toBeArray();
    });

    test('it handles disabled profile gracefully', function (): void {
        // Add a disabled profile
        config()->set('redactor.profiles.disabled_profile', [
            'enabled' => false,
            'strategies' => [BlockedKeysStrategy::class],
            'safe_keys' => [],
            'blocked_keys' => ['password'],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => null,
            'shannon_entropy' => ['enabled' => false],
        ]);

        $redactor = new Redactor;

        $data = ['password' => 'secret123'];
        $result = $redactor->redact($data, 'disabled_profile');

        // Should return original data without redaction when profile is disabled
        expect($result)->toBe($data);
    });

    test('it validates RedactorConfig creation from profile', function (): void {
        $config = RedactorConfig::fromConfig('strict');

        expect($config->profile)->toBe('strict')
            ->and($config->enabled)->toBeTrue()
            ->and($config->replacement)->toBe('[STRICT_REDACTED]')
            ->and($config->trackRedactedKeys)->toBeTrue()
            ->and($config->safeKeys)->toContain('id')
            ->and($config->blockedKeys)->toContain('password')
            ->and($config->blockedKeys)->toContain('name')
            ->and($config->maxObjectSize)->toBe(25);
    });
});
