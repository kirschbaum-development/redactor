<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Strategies\RedactionStrategyInterface;

describe('Redactor Strategy Priority Tests', function () {
    it('prioritizes safe_keys over blocked_keys', function () {
        // Explicit profile for priority testing
        config()->set('redactor.default_profile', 'priority_test');
        config()->set('redactor.profiles.priority_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
            ],
            'safe_keys' => ['id', 'email'],
            'blocked_keys' => ['email'],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => false,
                'threshold' => 4.8,
                'min_length' => 25,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'id' => '12345',
            'email' => 'user@example.com',
        ];

        $result = $redactor->redact($context);

        // Safe keys should always show unredacted, even if they're in blocked_keys
        expect($result['id'])->toBe('12345')
            ->and($result['email'])->toBe('user@example.com')
            ->and($result)->not->toHaveKey('_redacted');
    });

    it('prioritizes blocked_keys over regex patterns', function () {
        // Explicit profile for blocked keys vs regex priority
        config()->set('redactor.default_profile', 'blocked_vs_regex_test');
        config()->set('redactor.profiles.blocked_vs_regex_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\RegexPatternsStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => ['user_email'],
            'patterns' => [
                'email' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/',
            ],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => false,
                'threshold' => 4.8,
                'min_length' => 25,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'user_email' => 'user@example.com',
            'message' => 'Contact me at admin@example.com',
        ];

        $result = $redactor->redact($context);

        // user_email should be redacted due to blocked_keys
        // message should be redacted due to regex pattern
        expect($result['user_email'])->toBe('[REDACTED]')
            ->and($result['message'])->toBe('[REDACTED]')
            ->and($result['_redacted'])->toBeTrue();
    });

    it('prioritizes regex patterns over shannon entropy', function () {
        // Explicit profile for regex vs entropy priority
        config()->set('redactor.default_profile', 'regex_vs_entropy_test');
        config()->set('redactor.profiles.regex_vs_entropy_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\RegexPatternsStrategy::class,
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [
                'test_pattern' => '/test_secret_\d+/',
            ],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 1.0, // Very low threshold
                'min_length' => 10,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'data' => 'test_secret_123', // Matches regex
            'random' => 'abcdefghijklmnopqrstuvwxyz', // High entropy but no regex match
        ];

        $result = $redactor->redact($context);

        expect($result['data'])->toBe('[REDACTED]') // Redacted by regex
            ->and($result['random'])->toBe('[REDACTED]') // Redacted by entropy
            ->and($result['_redacted'])->toBeTrue();
    });
});

describe('Redactor Safe Keys Strategy Tests', function () {
    it('never redacts safe keys', function () {
        // Explicit profile for safe keys testing
        config()->set('redactor.default_profile', 'safe_keys_test');
        config()->set('redactor.profiles.safe_keys_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
            ],
            'safe_keys' => ['id', 'uuid', 'created_at', 'updated_at'],
            'blocked_keys' => ['password', 'secret'],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => false,
                'threshold' => 4.8,
                'min_length' => 25,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'id' => 12345,
            'uuid' => '550e8400-e29b-41d4-a716-446655440000',
            'created_at' => '2023-01-01T00:00:00Z',
            'updated_at' => '2023-01-02T00:00:00Z',
            'password' => 'secret123',
        ];

        $result = $redactor->redact($context);

        expect($result['id'])->toBe(12345)
            ->and($result['uuid'])->toBe('550e8400-e29b-41d4-a716-446655440000')
            ->and($result['created_at'])->toBe('2023-01-01T00:00:00Z')
            ->and($result['updated_at'])->toBe('2023-01-02T00:00:00Z')
            ->and($result['password'])->toBe('[REDACTED]')
            ->and($result['_redacted'])->toBeTrue();
    });

    it('handles safe keys case-insensitively', function () {
        // Explicit profile for case-insensitive safe keys testing
        config()->set('redactor.default_profile', 'safe_keys_case_test');
        config()->set('redactor.profiles.safe_keys_case_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
            ],
            'safe_keys' => ['id', 'uuid', 'created_at', 'updated_at'],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => false,
                'threshold' => 4.8,
                'min_length' => 25,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'ID' => 12345,
            'UUID' => '550e8400-e29b-41d4-a716-446655440000',
            'Created_At' => '2023-01-01T00:00:00Z',
            'UPDATED_AT' => '2023-01-02T00:00:00Z',
        ];

        $result = $redactor->redact($context);

        expect($result['ID'])->toBe(12345)
            ->and($result['UUID'])->toBe('550e8400-e29b-41d4-a716-446655440000')
            ->and($result['Created_At'])->toBe('2023-01-01T00:00:00Z')
            ->and($result['UPDATED_AT'])->toBe('2023-01-02T00:00:00Z')
            ->and($result)->not->toHaveKey('_redacted');
    });
});

describe('Redactor Blocked Keys Strategy Tests', function () {
    it('always redacts blocked keys', function () {
        // Explicit profile for blocked keys testing
        config()->set('redactor.default_profile', 'blocked_keys_test');
        config()->set('redactor.profiles.blocked_keys_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => ['email', 'ssn', 'ein'],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => false,
                'threshold' => 4.8,
                'min_length' => 25,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'email' => 'user@example.com',
            'ssn' => '123-45-6789',
            'ein' => '12-3456789',
            'name' => 'John Doe',
        ];

        $result = $redactor->redact($context);

        expect($result['email'])->toBe('[REDACTED]')
            ->and($result['ssn'])->toBe('[REDACTED]')
            ->and($result['ein'])->toBe('[REDACTED]')
            ->and($result['name'])->toBe('John Doe')
            ->and($result['_redacted'])->toBeTrue();
    });

    it('handles blocked keys case-insensitively', function () {
        // Explicit profile for case-insensitive blocked keys testing
        config()->set('redactor.default_profile', 'blocked_keys_case_test');
        config()->set('redactor.profiles.blocked_keys_case_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => ['email', 'ssn', 'ein'],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => false,
                'threshold' => 4.8,
                'min_length' => 25,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'EMAIL' => 'user@example.com',
            'Ssn' => '123-45-6789',
            'EIN' => '12-3456789',
        ];

        $result = $redactor->redact($context);

        expect($result['EMAIL'])->toBe('[REDACTED]')
            ->and($result['Ssn'])->toBe('[REDACTED]')
            ->and($result['EIN'])->toBe('[REDACTED]')
            ->and($result['_redacted'])->toBeTrue();
    });
});

describe('Redactor Regex Patterns Strategy Tests', function () {
    it('redacts strings matching regex patterns', function () {
        // Explicit profile for regex patterns testing
        config()->set('redactor.default_profile', 'regex_patterns_test');
        config()->set('redactor.profiles.regex_patterns_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\RegexPatternsStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [
                'email' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/',
                'credit_card' => '/\b(?:\d[ -]*?){13,16}\b/',
                'phone' => '/\+?\d[\d -]{8,14}\d/',
            ],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => false,
                'threshold' => 4.8,
                'min_length' => 25,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'user_message' => 'Contact me at john@example.com',
            'payment_info' => 'Credit card: 4532-1234-5678-9012',
            'contact' => 'Call me at +1-555-123-4567',
            'normal_text' => 'This is just normal text',
        ];

        $result = $redactor->redact($context);

        expect($result['user_message'])->toBe('[REDACTED]')
            ->and($result['payment_info'])->toBe('[REDACTED]')
            ->and($result['contact'])->toBe('[REDACTED]')
            ->and($result['normal_text'])->toBe('This is just normal text')
            ->and($result['_redacted'])->toBeTrue();
    });

    it('handles multiple patterns in same string', function () {
        // Explicit profile for multiple patterns testing
        config()->set('redactor.default_profile', 'multiple_patterns_test');
        config()->set('redactor.profiles.multiple_patterns_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\RegexPatternsStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [
                'email' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/',
                'phone' => '/\+?\d[\d -]{8,14}\d/',
            ],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => false,
                'threshold' => 4.8,
                'min_length' => 25,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'contact_info' => 'Email: john@example.com, Phone: +1-555-123-4567',
            'simple_text' => 'No sensitive data here',
        ];

        $result = $redactor->redact($context);

        expect($result['contact_info'])->toBe('[REDACTED]') // Contains both email and phone
            ->and($result['simple_text'])->toBe('No sensitive data here')
            ->and($result['_redacted'])->toBeTrue();
    });
});

describe('Strategy Management Tests', function () {
    it('returns all registered strategies via getStrategies method', function () {
        // Explicit profile for strategy management testing
        config()->set('redactor.default_profile', 'strategy_management_test');
        config()->set('redactor.profiles.strategy_management_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\RegexPatternsStrategy::class,
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            'safe_keys' => ['id'],
            'blocked_keys' => ['password'],
            'patterns' => [
                'email' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/',
            ],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.8,
                'min_length' => 25,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;
        $strategies = $redactor->getStrategies();

        expect($strategies)->toBeArray()
            ->and(count($strategies))->toBe(4);

        // Verify strategies are in priority order
        expect($strategies[0])->toBeInstanceOf(\Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class)
            ->and($strategies[1])->toBeInstanceOf(\Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class)
            ->and($strategies[2])->toBeInstanceOf(\Kirschbaum\Redactor\Strategies\RegexPatternsStrategy::class)
            ->and($strategies[3])->toBeInstanceOf(\Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class);
    });

    it('demonstrates strategy separation by removing a strategy', function () {
        // Explicit profile without Shannon entropy strategy
        config()->set('redactor.default_profile', 'strategy_removal_test');
        config()->set('redactor.profiles.strategy_removal_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\RegexPatternsStrategy::class,
                // Note: shannon_entropy strategy is not included
            ],
            'safe_keys' => ['id'],
            'blocked_keys' => ['password'],
            'patterns' => [
                'email' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/',
            ],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => false,
                'threshold' => 4.8,
                'min_length' => 25,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'id' => 12345,
            'password' => 'secret123',
            'email_text' => 'Contact: user@example.com',
            'high_entropy' => 'sk-1234567890abcdef1234567890abcdef12345678', // Would be caught by Shannon entropy
        ];

        $result = $redactor->redact($context);

        expect($result['id'])->toBe(12345) // Safe key
            ->and($result['password'])->toBe('[REDACTED]') // Blocked key
            ->and($result['email_text'])->toBe('[REDACTED]') // Regex pattern
            ->and($result['high_entropy'])->toBe('sk-1234567890abcdef1234567890abcdef12345678') // Not redacted (no Shannon entropy strategy)
            ->and($result['_redacted'])->toBeTrue();
    });

    it('handles edge case where strategy receives unexpected value type', function () {
        // Explicit profile for edge case testing
        config()->set('redactor.default_profile', 'edge_case_test');
        config()->set('redactor.profiles.edge_case_test', [
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
            'shannon_entropy' => [
                'enabled' => false,
                'threshold' => 4.8,
                'min_length' => 25,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        // Create a custom strategy that handles unexpected types
        $customStrategy = new class implements RedactionStrategyInterface
        {
            public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
            {
                return $key === 'special_key' && is_array($value);
            }

            public function handle(mixed $value, string $key, RedactionContext $context): mixed
            {
                $context->markRedacted();

                return ['custom_redacted' => true];
            }
        };

        // Register the custom strategy
        $redactor->registerCustomStrategy('custom_test', $customStrategy);

        // Update profile to include the custom strategy first
        config()->set('redactor.profiles.edge_case_test.strategies', [
            'custom_test', // Custom strategy by name
            \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
            \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
        ]);

        $context = [
            'id' => 12345,
            'password' => 'secret123',
            'special_key' => ['nested' => 'data'],
            'normal_key' => 'normal_value',
        ];

        $result = $redactor->redact($context);

        expect($result['id'])->toBe(12345) // Safe key
            ->and($result['password'])->toBe('[REDACTED]') // Blocked key
            ->and($result['special_key'])->toBe(['custom_redacted' => true]) // Custom strategy
            ->and($result['normal_key'])->toBe('normal_value') // No strategy handles this
            ->and($result['_redacted'])->toBeTrue();
    });
});

describe('Strategy Edge Cases and Coverage Tests', function () {
    beforeEach(function () {
        config()->set('redactor.default_profile', 'default');
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
            'shannon_entropy' => ['enabled' => false],
        ]);
    });

    it('handles non-string strategy classes in profile configuration', function () {
        // Test when strategy class is not a string
        config()->set('redactor.profiles.default.strategies', [
            \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
            123, // Non-string strategy - should be skipped
            null, // Non-string strategy - should be skipped
            \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
        ]);

        $redactor = new Redactor;
        $strategies = $redactor->getStrategies('default');

        // Should have 2 strategies (the 2 valid ones), skipping the non-string entries
        expect($strategies)->toHaveCount(2);
    });

    it('handles non-existent strategy classes', function () {
        // Test createStrategyInstance returning null for non-existent class
        config()->set('redactor.profiles.default.strategies', [
            'NonExistentStrategyClass', // This will return null
        ]);

        $redactor = new Redactor;
        $strategies = $redactor->getStrategies('default');

        // Should have no strategies since the class doesn't exist
        expect($strategies)->toHaveCount(0);
    });

    it('handles classes that exist but do not implement RedactionStrategyInterface', function () {
        // Test the case where class exists but doesn't implement RedactionStrategyInterface
        config()->set('redactor.profiles.default.strategies', [
            \stdClass::class, // Valid class but not a RedactionStrategyInterface
        ]);

        $redactor = new Redactor;
        $strategies = $redactor->getStrategies('default');

        // Should have no strategies since stdClass doesn't implement RedactionStrategyInterface
        expect($strategies)->toHaveCount(0);
    });

    it('handles non-array custom_strategies configuration', function () {
        // Test when custom_strategies config is not an array
        config()->set('redactor.custom_strategies', 'not_an_array');

        $redactor = new Redactor;

        // Should not throw an error and work normally
        expect($redactor->getStrategies('default'))->toBeArray();
    });

    it('handles invalid custom strategy configurations', function () {
        // Test various invalid custom strategy configurations
        config()->set('redactor.custom_strategies', [
            'valid_strategy' => TestValidCustomStrategy::class,
            123 => TestValidCustomStrategy::class, // Non-string name
            'invalid_class' => 'NonExistentClass', // Class doesn't exist
            'not_strategy' => \stdClass::class, // Not a RedactionStrategyInterface
            'invalid_type' => 123, // Not a string class name
        ]);

        $redactor = new Redactor;

        // Should only load the valid strategy
        $customStrategies = $redactor->getStrategies('default');
        expect($customStrategies)->toBeArray();
    });

    it('handles LargeStringStrategy with non-string input', function () {
        // Test guard clause for non-string values in LargeStringStrategy
        config()->set('redactor.profiles.default.strategies', [
            \Kirschbaum\Redactor\Strategies\LargeStringStrategy::class,
        ]);
        config()->set('redactor.profiles.default.max_value_length', 10);

        // Use reflection to manually test the strategy with non-string input
        $strategy = new \Kirschbaum\Redactor\Strategies\LargeStringStrategy;
        $config = \Kirschbaum\Redactor\RedactorConfig::fromConfig('default');
        $context = new \Kirschbaum\Redactor\RedactionContext($config);

        // This should trigger the guard clause
        $result = $strategy->handle(123, 'test_key', $context);

        expect($result)->toBe(123); // Should return original value
    });

    it('uses deprecated addStrategy method for backward compatibility', function () {
        // Test deprecated addStrategy method
        $redactor = new Redactor;
        $customStrategy = new TestValidCustomStrategy;

        $redactor->addStrategy($customStrategy);

        // Should register the strategy (check that it doesn't throw an error)
        $strategies = $redactor->getStrategies('default');
        expect($strategies)->toBeArray();
    });

    it('uses deprecated removeStrategy method for backward compatibility', function () {
        // Test deprecated removeStrategy method
        $redactor = new Redactor;

        $redactor->removeStrategy('some_strategy');

        // Should clear cached strategies (no exception should be thrown)
        expect($redactor->getStrategies('default'))->toBeArray();
    });
});

// Test helper class for strategy tests
class TestValidCustomStrategy implements \Kirschbaum\Redactor\Strategies\RedactionStrategyInterface
{
    public function shouldHandle(mixed $value, string $key, \Kirschbaum\Redactor\RedactionContext $context): bool
    {
        return false;
    }

    public function handle(mixed $value, string $key, \Kirschbaum\Redactor\RedactionContext $context): mixed
    {
        return $value;
    }
}
