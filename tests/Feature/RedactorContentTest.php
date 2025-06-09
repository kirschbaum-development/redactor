<?php

declare(strict_types=1);

use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Strategies\RedactionStrategyInterface;
use Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy;

// Simple test object without toArray method
class SimpleTestObject
{
    public $prop1 = 'value1';

    public $prop2 = 'value2';

    public $prop3 = 'value3';

    public function getData()
    {
        return ['prop1' => $this->prop1, 'prop2' => $this->prop2, 'prop3' => $this->prop3];
    }
}

// Test object with toArray method for testing array conversion
class TestObjectWithToArray
{
    public $prop1 = 'value1';

    public $prop2 = 'value2';

    public $prop3 = 'value3';

    public function toArray(): array
    {
        return ['prop1' => $this->prop1, 'prop2' => $this->prop2, 'prop3' => $this->prop3];
    }
}

describe('Redactor Content Tests', function () {
    beforeEach(function () {
        // Set up test configurations for different scenarios
        // This replaces the need for dynamic strategy addition/removal
        config()->set('redactor.profiles.no_shannon', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\LargeObjectStrategy::class,
                \Kirschbaum\Redactor\Strategies\LargeStringStrategy::class,
                \Kirschbaum\Redactor\Strategies\RegexPatternsStrategy::class,
                // Note: No ShannonEntropyStrategy
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

        config()->set('redactor.profiles.test_shannon', [
            'enabled' => true,
            'strategies' => [\Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => null,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 3.0,
                'min_length' => 10,
                'exclusion_patterns' => ['/^[0-9a-f]+$/i'],
            ],
        ]);

        config()->set('redactor.profiles.small_object_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\LargeObjectStrategy::class,
                \Kirschbaum\Redactor\Strategies\LargeStringStrategy::class,
                \Kirschbaum\Redactor\Strategies\RegexPatternsStrategy::class,
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
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
            'max_object_size' => 1, // Very small
            'shannon_entropy' => ['enabled' => false],
        ]);
    });

    test('it returns zero entropy when no ShannonEntropyStrategy is found during entropy calculation', function () {
        $redactor = new Redactor;

        // Use profile without ShannonEntropyStrategy - should return 0.0
        $strategies = $redactor->getStrategies('no_shannon');
        $hasShannon = false;
        foreach ($strategies as $strategy) {
            if ($strategy instanceof ShannonEntropyStrategy) {
                $hasShannon = true;
                break;
            }
        }

        expect($hasShannon)->toBeFalse();

        // calculateShannonEntropy uses default profile by default, so we need to check directly
        // Since the method searches through strategies in the default profile, and our no_shannon profile
        // doesn't have ShannonEntropyStrategy, we need to test with empty strategies
        $entropy = $redactor->calculateShannonEntropy('high-entropy-string-xyz123');

        // The default profile still has ShannonEntropyStrategy, so let's verify the logic
        // by testing the actual case where no strategy is found
        expect($entropy)->toBeGreaterThan(0.0); // Default profile has the strategy

        // Create redactor instance that specifically uses no_shannon profile for this test
        // Since calculateShannonEntropy uses default profile, we test the edge case directly
        config()->set('redactor.default_profile', 'no_shannon');
        $noShannonRedactor = new Redactor;
        $entropyNoStrategy = $noShannonRedactor->calculateShannonEntropy('high-entropy-string-xyz123');
        expect($entropyNoStrategy)->toBe(0.0);
    });

    test('it returns false when no ShannonEntropyStrategy is found during pattern checking', function () {
        // Set profile without ShannonEntropyStrategy as default
        config()->set('redactor.default_profile', 'no_shannon');
        $redactor = new Redactor;
        $config = RedactorConfig::fromConfig('no_shannon');

        // Should return false when no strategy found
        $isCommon = $redactor->isCommonPattern('192.168.1.1', $config);

        expect($isCommon)->toBe(false);
    });

    test('it allows long hex strings to bypass common pattern exclusion for entropy checking', function () {
        $redactor = new Redactor;
        $config = RedactorConfig::fromConfig('test_shannon');

        // Test that a long hex string (>=32 chars) continues past the pattern match
        $longHex = str_repeat('a1b2c3d4', 8); // 64 characters

        // This will exercise the specific branch where hex strings >= 32 continue
        $isCommon = $redactor->isCommonPattern($longHex, $config);

        // The method should return false for long hex strings, allowing them to be entropy-checked
        expect($isCommon)->toBe(false);

        // Short hex should be considered common
        $shortHex = 'a1b2c3d4';
        $isCommonShort = $redactor->isCommonPattern($shortHex, $config);
        expect($isCommonShort)->toBe(true);
    });

    test('it handles exceptions thrown by toArray method during object redaction', function () {
        $redactor = new Redactor;

        // Create an object with a toArray method that throws an exception
        $objectWithBadToArray = new class
        {
            public function toArray()
            {
                throw new Exception('toArray failed');
            }
        };

        $data = ['bad_object' => $objectWithBadToArray];
        $result = $redactor->redact($data);

        // Should fall back to JSON encoding approach and handle gracefully
        expect($result)->toHaveKey('bad_object');
    });

    test('it skips large object redaction when feature is disabled', function () {
        // Create profile with large object redaction disabled
        config()->set('redactor.profiles.no_large_objects', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\LargeStringStrategy::class,
                \Kirschbaum\Redactor\Strategies\RegexPatternsStrategy::class,
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
                // Note: No LargeObjectStrategy
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false, // Disabled
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => false,
                'threshold' => 4.8,
                'min_length' => 25,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        // Create a large array
        $largeArray = array_fill(0, 150, 'value');

        $data = ['large_data' => $largeArray];
        $result = $redactor->redact($data, 'no_large_objects');

        // Should not be redacted when feature is disabled
        expect($result['large_data'])->toBe($largeArray);
    });

    test('it wraps non-array strategy results in redacted array structure', function () {
        // Create a custom strategy that returns a string when processing arrays
        $customStrategy = new class implements RedactionStrategyInterface
        {
            public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
            {
                return is_array($value) && count($value) > 2;
            }

            public function handle(mixed $value, string $key, RedactionContext $context): mixed
            {
                $context->markRedacted();

                return '[CUSTOM_ARRAY_REDACTED]'; // Return a string, not an array
            }
        };

        // Register the custom strategy and create a profile that uses it
        $redactor = new Redactor;
        $redactor->registerCustomStrategy('array_strategy', $customStrategy);

        // Create profile with custom strategy
        config()->set('redactor.profiles.custom_array_test', [
            'enabled' => true,
            'strategies' => [
                'array_strategy', // Custom strategy first
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

        // Create an array that will be processed by our custom strategy
        $largeArray = ['item1', 'item2', 'item3', 'item4'];

        $result = $redactor->redact($largeArray, 'custom_array_test');

        // Should wrap the non-array result in _redacted_array structure
        expect($result)->toBeArray()
            ->and($result)->toHaveKey('_redacted_array')
            ->and($result['_redacted_array'])->toBe('[CUSTOM_ARRAY_REDACTED]')
            ->and($result['_redacted'])->toBeTrue();
    });

    test('it removes keys when strategy returns removal signal', function () {
        // Create a custom strategy that removes specific keys by returning __REDACTOR_REMOVE_OBJECT__
        $removeStrategy = new class implements RedactionStrategyInterface
        {
            public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
            {
                return $key === 'remove_me' || $key === 'also_remove';
            }

            public function handle(mixed $value, string $key, RedactionContext $context): mixed
            {
                $context->markRedacted();

                return '__REDACTOR_REMOVE_OBJECT__'; // Signal that this key should be removed
            }
        };

        // Register the custom strategy and create a profile that uses it
        $redactor = new Redactor;
        $redactor->registerCustomStrategy('remove_strategy', $removeStrategy);

        // Create profile with custom strategy
        config()->set('redactor.profiles.remove_test', [
            'enabled' => true,
            'strategies' => [
                'remove_strategy', // Custom strategy first
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

        // Create data with keys that should be removed
        $data = [
            'keep_me' => 'this stays',
            'remove_me' => 'this gets removed',
            'normal_key' => 'this also stays',
            'also_remove' => 'this also gets removed',
        ];

        $result = $redactor->redact($data, 'remove_test');

        // Should remove the specified keys and keep the others
        expect($result)->toBeArray()
            ->and($result)->toHaveKey('keep_me')
            ->and($result['keep_me'])->toBe('this stays')
            ->and($result)->toHaveKey('normal_key')
            ->and($result['normal_key'])->toBe('this also stays')
            ->and($result)->not->toHaveKey('remove_me') // This key should be removed
            ->and($result)->not->toHaveKey('also_remove') // This key should also be removed
            ->and($result['_redacted'])->toBeTrue();
    });

    test('it handles large objects that exceed size limits during property counting', function () {
        // Create profile with very small max object size
        config()->set('redactor.profiles.small_object_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\LargeObjectStrategy::class,
                \Kirschbaum\Redactor\Strategies\LargeStringStrategy::class,
                \Kirschbaum\Redactor\Strategies\RegexPatternsStrategy::class,
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
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
            'max_object_size' => 1, // Very small
            'shannon_entropy' => ['enabled' => false],
        ]);

        $redactor = new Redactor;

        // Create a large object that will fail during property counting in the handle method
        $largeObject = new stdClass;
        $largeObject->prop1 = 'value1';
        $largeObject->prop2 = 'value2';

        $data = ['large_obj' => $largeObject];
        $result = $redactor->redact($data, 'small_object_test');

        // Should still redact and use the fallback message
        expect($result['large_obj'])->toHaveKey('_large_object_redacted');
        $message = $result['large_obj']['_large_object_redacted'];
        expect($message)->toContain('stdClass');
    });

    test('it handles large objects detected via JSON encoding when toArray is unavailable', function () {
        // Create profile with small max object size
        config()->set('redactor.profiles.json_size_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\LargeObjectStrategy::class,
                \Kirschbaum\Redactor\Strategies\LargeStringStrategy::class,
                \Kirschbaum\Redactor\Strategies\RegexPatternsStrategy::class,
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
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
            'max_object_size' => 2, // Small
            'shannon_entropy' => ['enabled' => false],
        ]);

        $redactor = new Redactor;

        // Create object without toArray method that will be large when JSON decoded
        $largeObject = new class
        {
            public $prop1 = 'value1';

            public $prop2 = 'value2';

            public $prop3 = 'value3';

            public $prop4 = 'value4';
        };

        $data = ['large_obj' => $largeObject];
        $result = $redactor->redact($data, 'json_size_test');

        expect($result['large_obj'])->toHaveKey('_large_object_redacted');
    });

    test('it handles objects with toArray method that throws exception during size detection', function () {
        config(['redactor.max_object_size' => 2]);

        $redactor = new Redactor;

        // Create object with toArray that throws an exception during size detection
        $largeObject = new class
        {
            public function toArray()
            {
                throw new Exception('Failed during detection');
            }
        };

        $data = ['large_obj' => $largeObject];
        $result = $redactor->redact($data);

        // Should handle the exception gracefully
        expect($result)->toHaveKey('large_obj');
    });

    test('it handles objects with JSON encoding failures during size detection', function () {
        config(['redactor.max_object_size' => 2]);

        $redactor = new Redactor;

        // Create object that will fail JSON encoding during size detection
        $largeObject = new class
        {
            public $circular;

            public function __construct()
            {
                $this->circular = $this; // Create circular reference
            }
        };

        $data = ['large_obj' => $largeObject];
        $result = $redactor->redact($data);

        // Should handle the JSON encoding failure gracefully
        expect($result)->toHaveKey('large_obj');
    });

    test('it returns strategy-processed objects directly when handled by custom strategies', function () {
        // Create a custom strategy that specifically handles certain objects
        $objectStrategy = new class implements RedactionStrategyInterface
        {
            public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
            {
                return is_object($value) && property_exists($value, 'sensitive_data');
            }

            public function handle(mixed $value, string $key, RedactionContext $context): mixed
            {
                $context->markRedacted();

                return '[OBJECT_REDACTED_BY_STRATEGY]'; // Return a string instead of the object
            }
        };

        // Register the custom strategy and create a profile that uses it
        $redactor = new Redactor;
        $redactor->registerCustomStrategy('object_strategy', $objectStrategy);

        // Create profile with custom strategy
        config()->set('redactor.profiles.object_strategy_test', [
            'enabled' => true,
            'strategies' => [
                'object_strategy', // Custom strategy first
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

        // Create an object that should be handled by our strategy
        $sensitiveObject = new stdClass;
        $sensitiveObject->sensitive_data = 'secret information';
        $sensitiveObject->normal_data = 'normal information';

        // Test direct object redaction - this will call redactObject method directly
        $result = $redactor->redact($sensitiveObject, 'object_strategy_test');

        // The object should be replaced by the strategy return value
        expect($result)->toBe('[OBJECT_REDACTED_BY_STRATEGY]');

        // Also test as part of an array to ensure both paths work
        $data = ['obj' => $sensitiveObject];
        $arrayResult = $redactor->redact($data, 'object_strategy_test');

        expect($arrayResult)->toBeArray()
            ->and($arrayResult['obj'])->toBe('[OBJECT_REDACTED_BY_STRATEGY]')
            ->and($arrayResult['_redacted'])->toBeTrue();
    });

    test('it returns all registered strategies via getStrategies method', function () {
        $redactor = new Redactor;

        // Get the initial strategies from default profile
        $strategies = $redactor->getStrategies();

        // Should have the 6 default strategies
        expect($strategies)->toHaveCount(6);

        // Verify they are strategy instances
        foreach ($strategies as $strategy) {
            expect($strategy)->toBeInstanceOf(RedactionStrategyInterface::class);
        }

        // Test with a custom profile that includes a registered custom strategy
        $customStrategy = new class implements RedactionStrategyInterface
        {
            public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
            {
                return false; // Never handles anything
            }

            public function handle(mixed $value, string $key, RedactionContext $context): mixed
            {
                return $value;
            }
        };

        // Register custom strategy and create profile with it
        $redactor->registerCustomStrategy('test_strategy', $customStrategy);

        config()->set('redactor.profiles.custom_strategy_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\LargeObjectStrategy::class,
                \Kirschbaum\Redactor\Strategies\LargeStringStrategy::class,
                \Kirschbaum\Redactor\Strategies\RegexPatternsStrategy::class,
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
                'test_strategy', // Custom strategy
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

        // Should now have 7 strategies when using custom profile
        $strategiesWithCustom = $redactor->getStrategies('custom_strategy_test');
        expect($strategiesWithCustom)->toHaveCount(7);

        // Profile without custom strategy should still have 6
        $strategiesDefault = $redactor->getStrategies();
        expect($strategiesDefault)->toHaveCount(6);
    });

    test('it skips large object redaction when feature is disabled in configuration', function () {
        // Disable large object redaction
        config(['redactor.redact_large_objects' => false]);

        $redactor = new Redactor;

        // Create a large array that would normally be redacted
        $largeArray = array_fill(0, 100, 'value'); // Exceeds default maxObjectSize of 50

        // Create a large object that would normally be redacted
        $largeObject = new stdClass;
        for ($i = 0; $i < 60; $i++) {
            $propertyName = "prop$i";
            $largeObject->$propertyName = "value$i";
        }

        $data = [
            'large_array' => $largeArray,
            'large_object' => $largeObject,
        ];

        $result = $redactor->redact($data);

        // With redactLargeObjects disabled, large objects should not be redacted
        // They should be processed normally (converted to arrays for objects)
        expect($result['large_array'])->toBe($largeArray) // Array remains unchanged
            ->and($result['large_object'])->toBeArray() // Object converted to array normally
            ->and($result['large_object'])->toHaveKey('prop0') // Properties preserved
            ->and($result)->not->toHaveKey('_redacted'); // No redaction occurred
    });

    test('it redacts large objects when they exceed size limits', function () {
        // Use the small_object_test profile we already set up
        $redactor = new Redactor;

        // Create a large object that exceeds the max size
        $largeObject = new stdClass;
        $largeObject->prop1 = 'value1';
        $largeObject->prop2 = 'value2';
        $largeObject->prop3 = 'value3'; // Exceeds max size of 1

        $data = ['large_obj' => $largeObject];
        $result = $redactor->redact($data, 'small_object_test');

        // Should be redacted when object is too large
        expect($result['large_obj'])->toHaveKey('_large_object_redacted')
            ->and($result['_redacted'])->toBeTrue();
    });

    test('it handles objects with circular references gracefully', function () {
        $redactor = new Redactor;

        // Create an object with circular reference
        $problematicObject = new class
        {
            public $circular;

            public $prop1;

            public function __construct()
            {
                $this->circular = $this; // Circular reference
                $this->prop1 = 'value1';
            }
        };

        $data = ['problematic_obj' => $problematicObject];
        $result = $redactor->redact($data);

        // Should handle gracefully (either preserve or redact based on non_redactable_object_behavior)
        expect($result)->toHaveKey('problematic_obj');
    });

    test('it handles string values correctly in redaction process', function () {
        $redactor = new Redactor;

        $data = ['simple_string' => 'test_value'];
        $result = $redactor->redact($data);

        // Simple strings should pass through unless caught by other strategies
        expect($result['simple_string'])->toBe('test_value');
    });

    test('it handles objects with toArray method correctly', function () {
        $redactor = new Redactor;

        // Use an object that has a toArray method
        $objectWithToArray = new TestObjectWithToArray;

        $data = ['test_object' => $objectWithToArray];
        $result = $redactor->redact($data, 'small_object_test');

        // Should handle the object (either redact if large or convert to array)
        expect($result)->toHaveKey('test_object');
    });

    test('it handles complex objects with encoding issues gracefully', function () {
        $redactor = new Redactor;

        // Create an object that might cause encoding issues
        $complexObject = new class
        {
            public $prop1 = 'value1';

            public $prop2 = 'value2';

            public $circular;

            public function __construct()
            {
                $this->circular = $this; // Circular reference
            }
        };

        $data = ['complex_obj' => $complexObject];
        $result = $redactor->redact($data, 'small_object_test');

        // Should handle gracefully without throwing exceptions
        expect($result)->toHaveKey('complex_obj');
    });

    test('it allows long hex strings to bypass exclusion patterns in shannon entropy strategy', function () {
        // Create profile with Shannon entropy and hex exclusion pattern
        config()->set('redactor.profiles.hex_test', [
            'enabled' => true,
            'strategies' => [\Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => null,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 3.0, // Low threshold
                'min_length' => 10,
                'exclusion_patterns' => ['/^[0-9a-f]+$/i'], // Hex pattern
            ],
        ]);

        $redactor = new Redactor;

        // Create a long hex string (>= 32 chars) that should continue past the pattern match
        $longHex = str_repeat('a1b2c3d4', 8); // 64 characters, all hex

        $data = ['long_hex' => $longHex];
        $result = $redactor->redact($data, 'hex_test');

        // The long hex string should be redacted despite matching hex pattern
        expect($result['long_hex'])->toBe('[REDACTED]')
            ->and($result['_redacted'])->toBeTrue();

        // Verify short hex is NOT redacted (normal pattern matching)
        $shortHex = 'a1b2c3d4e5f6'; // 12 characters, hex
        $shortResult = $redactor->redact(['short_hex' => $shortHex], 'hex_test');
        expect($shortResult['short_hex'])->toBe('a1b2c3d4e5f6') // Not redacted
            ->and($shortResult)->not->toHaveKey('_redacted');
    });

    test('it calculates shannon entropy correctly', function () {
        $redactor = new Redactor;

        // Test the public calculateShannonEntropy method
        $highEntropyString = 'aB3$xY9#mK2@pL5!qR8%';
        $entropy = $redactor->calculateShannonEntropy($highEntropyString);

        // Should return a reasonable entropy value
        expect($entropy)->toBeGreaterThan(0.0)
            ->and($entropy)->toBeLessThan(8.0); // Max theoretical entropy for 8-bit chars
    });
});
