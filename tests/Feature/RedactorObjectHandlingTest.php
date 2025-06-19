<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Redactor;

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

describe('Redactor Large Object Tests', function () {
    beforeEach(function () {
        // Set up profile-based configuration for large object tests
        config()->set('redactor.default_profile', 'default');
        config()->set('redactor.profiles.default', [
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
            'max_object_size' => 3,
            'shannon_entropy' => [
                'enabled' => false,
                'threshold' => 4.8,
                'min_length' => 25,
                'exclusion_patterns' => [],
            ],
        ]);
    });

    it('redacts large arrays based on size', function () {
        $redactor = new Redactor;

        $smallArray = ['a' => 1, 'b' => 2];
        $largeArray = ['a' => 1, 'b' => 2, 'c' => 3, 'd' => 4, 'e' => 5];

        $context = [
            'small' => $smallArray,
            'large' => $largeArray,
        ];

        $result = $redactor->redact($context);

        expect($result['small'])->toBe($smallArray)
            ->and($result['large'])->toHaveKey('_large_object_redacted')
            ->and($result['large']['_large_object_redacted'])->toContain('[REDACTED]')
            ->and($result['large']['_large_object_redacted'])->toContain('(Array with 5 items)')
            ->and($result['_redacted'])->toBeTrue();
    });

    it('redacts large arrays when provided as top-level input', function () {
        $redactor = new Redactor;

        // Create a large array as the primary input (not nested within another structure)
        $largeArray = ['a' => 1, 'b' => 2, 'c' => 3, 'd' => 4, 'e' => 5]; // Exceeds max size of 3

        $result = $redactor->redact($largeArray);

        // When a large array is the top-level input, it should be redacted directly
        expect($result)->toBeArray()
            ->and($result)->toHaveKey('_large_object_redacted')
            ->and($result['_large_object_redacted'])->toContain('[REDACTED]')
            ->and($result['_large_object_redacted'])->toContain('(Array with 5 items)')
            ->and($result)->toHaveKey('_redacted')
            ->and($result['_redacted'])->toBeTrue();
    });

    it('redacts large objects based on property count', function () {
        $redactor = new Redactor;

        // Create an object with many properties
        $largeObject = new \stdClass;
        $largeObject->prop1 = 'value1';
        $largeObject->prop2 = 'value2';
        $largeObject->prop3 = 'value3';
        $largeObject->prop4 = 'value4';

        $context = ['large_obj' => $largeObject];
        $result = $redactor->redact($context);

        expect($result['large_obj'])->toHaveKey('_large_object_redacted')
            ->and($result['large_obj']['_large_object_redacted'])->toContain('[REDACTED]')
            ->and($result['large_obj']['_large_object_redacted'])->toContain('Object stdClass with 4 properties')
            ->and($result['_redacted'])->toBeTrue();
    });

    it('skips large object redaction when feature is disabled', function () {
        // Update the profile config for this test
        config()->set('redactor.profiles.default.redact_large_objects', false);

        $redactor = new Redactor;

        // Create a large array that would normally be redacted
        $largeArray = array_fill(0, 100, 'value'); // Exceeds default maxObjectSize of 50

        // Create a large object that would normally be redacted
        $largeObject = new \stdClass;
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

    it('handles large objects that exceed size limits during property counting', function () {
        config()->set('redactor.profiles.default.max_object_size', 1);

        $redactor = new Redactor;

        // Create a large object that will fail during property counting in the handle method
        $largeObject = new \stdClass;
        $largeObject->prop1 = 'value1';
        $largeObject->prop2 = 'value2';

        $data = ['large_obj' => $largeObject];
        $result = $redactor->redact($data);

        // Should still redact and use the fallback message
        expect($result['large_obj'])->toHaveKey('_large_object_redacted');
        $message = $result['large_obj']['_large_object_redacted'];
        expect($message)->toContain('stdClass');
    });

    it('handles large objects detected via JSON encoding when toArray is unavailable', function () {
        config()->set('redactor.profiles.default.max_object_size', 2);

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
        $result = $redactor->redact($data);

        expect($result['large_obj'])->toHaveKey('_large_object_redacted');
    });

});

describe('Redactor String Length Tests', function () {
    beforeEach(function () {
        // Set up profile-based configuration for string length tests
        config()->set('redactor.default_profile', 'default');
        config()->set('redactor.profiles.default', [
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
            'max_value_length' => 50,
            'redact_large_objects' => true,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => false,
                'threshold' => 4.8,
                'min_length' => 25,
                'exclusion_patterns' => [],
            ],
        ]);
    });

    it('redacts strings that exceed the maximum value length', function () {
        $redactor = new Redactor;

        $shortString = 'This is a short string';
        $longString = str_repeat('This is a very long string that exceeds the max length. ', 10);

        $context = [
            'short' => $shortString,
            'long' => $longString,
        ];

        $result = $redactor->redact($context);

        expect($result['short'])->toBe($shortString)
            ->and($result['long'])->toContain('[REDACTED]')
            ->and($result['long'])->toContain('(String with')
            ->and($result['_redacted'])->toBeTrue();
    });

    it('handles string length redaction when value length is null (no limit)', function () {
        // Update the profile config to remove length limit
        config()->set('redactor.profiles.default.max_value_length', null);

        $redactor = new Redactor;

        $veryLongString = str_repeat('This is a very long string. ', 100);

        $result = $redactor->redact($veryLongString);

        // Should not be redacted due to length since limit is disabled
        expect($result)->toBe($veryLongString);
    });
});

describe('Redactor Object Handling Tests', function () {
    beforeEach(function () {
        // Set up profile-based configuration for object handling tests
        config()->set('redactor.default_profile', 'default');
        config()->set('redactor.profiles.default', [
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
            'blocked_keys' => ['password'],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => true,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => false,
                'threshold' => 4.8,
                'min_length' => 25,
                'exclusion_patterns' => [],
            ],
        ]);
    });

    it('redacts objects with toArray method', function () {
        $redactor = new Redactor;

        $object = new class
        {
            public function toArray(): array
            {
                return [
                    'id' => 123,
                    'password' => 'secret123',
                    'name' => 'John Doe',
                ];
            }
        };

        $result = $redactor->redact($object);

        expect($result)->toBeArray()
            ->and($result['id'])->toBe(123)
            ->and($result['password'])->toBe('[REDACTED]')
            ->and($result['name'])->toBe('John Doe')
            ->and($result['_redacted'])->toBeTrue();
    });

    it('redacts objects via JSON serialization when toArray is not available', function () {
        $redactor = new Redactor;

        $object = new \stdClass;
        $object->id = 456;
        $object->password = 'secret456';
        $object->name = 'Jane Doe';

        $result = $redactor->redact($object);

        expect($result)->toBeArray()
            ->and($result['id'])->toBe(456)
            ->and($result['password'])->toBe('[REDACTED]')
            ->and($result['name'])->toBe('Jane Doe')
            ->and($result['_redacted'])->toBeTrue();
    });

    it('handles objects with blocked and safe keys correctly', function () {
        // Update the profile config for this test
        config()->set('redactor.profiles.default.blocked_keys', ['password', 'secret']);
        config()->set('redactor.profiles.default.safe_keys', ['id']);

        $redactor = new Redactor;

        $object = new \stdClass;
        $object->id = 789;
        $object->password = 'secret789';
        $object->secret = 'hidden_value';
        $object->name = 'Test User';

        $result = $redactor->redact($object);

        expect($result)->toBeArray()
            ->and($result['id'])->toBe(789) // Safe key
            ->and($result['password'])->toBe('[REDACTED]') // Blocked key
            ->and($result['secret'])->toBe('[REDACTED]') // Blocked key
            ->and($result['name'])->toBe('Test User') // Normal key
            ->and($result['_redacted'])->toBeTrue();
    });

    it('handles object with toArray method that throws an exception', function () {
        $redactor = new Redactor;

        $objectWithBadToArray = new class
        {
            public function toArray()
            {
                throw new \Exception('toArray failed');
            }
        };

        $result = $redactor->redact($objectWithBadToArray);

        // Should fall back to JSON encoding approach and handle gracefully
        expect($result)->toBeArray(); // Should still be processed as an array
    });

    it('handles object with toArray method that returns non-array', function () {
        $redactor = new Redactor;

        $objectWithBadToArray = new class
        {
            public function toArray()
            {
                return 'not_an_array'; // Invalid return type
            }
        };

        $result = $redactor->redact($objectWithBadToArray);

        // Should fall back to JSON encoding approach
        expect($result)->toBeArray();
    });

    it('handles object with circular reference via JSON encoding', function () {
        $redactor = new Redactor;

        // Create circular reference object that can't be JSON serialized
        $object = new \stdClass;
        $object->id = 999;
        $object->self = $object; // Circular reference

        // Based on default preserve behavior, it should return the original object
        $result = $redactor->redact($object);

        expect($result)->toBe($object); // Should preserve the original object
    });

    it('processes JsonSerializable objects correctly', function () {
        $redactor = new Redactor;

        $jsonObject = new class implements \JsonSerializable
        {
            public function jsonSerialize(): array
            {
                return [
                    'id' => 321,
                    'password' => 'json_secret',
                    'data' => 'some_data',
                ];
            }
        };

        $result = $redactor->redact($jsonObject);

        expect($result)->toBeArray()
            ->and($result['id'])->toBe(321)
            ->and($result['password'])->toBe('[REDACTED]')
            ->and($result['data'])->toBe('some_data')
            ->and($result['_redacted'])->toBeTrue();
    });

    it('handles objects that become problematic during toArray conversion', function () {
        $redactor = new Redactor;

        // Create an object that has a toArray method but creates issues during conversion
        $problematicObject = new class
        {
            /** @var resource */
            public $resource;

            public function __construct()
            {
                $this->resource = fopen('php://memory', 'r+'); // Resource that can't be JSON encoded
            }

            public function toArray(): array
            {
                return [
                    'id' => 123,
                    'resource' => $this->resource, // This will cause JSON encoding to fail
                    'password' => 'secret',
                ];
            }
        };

        $result = $redactor->redact($problematicObject);

        // Should handle the problematic object gracefully
        // The toArray method works but JSON encoding will fail, so it should be processed as an array
        expect($result)->toBeArray()
            ->and($result['id'])->toBe(123)
            ->and($result['password'])->toBe('[REDACTED]')
            ->and($result['_redacted'])->toBeTrue();
    });

});

describe('Redactor Non-Redactable Object Behavior Tests', function () {
    beforeEach(function () {
        // Set up profile-based configuration for non-redactable object behavior tests
        config()->set('redactor.default_profile', 'default');
        config()->set('redactor.profiles.default', [
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
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => false,
                'threshold' => 4.8,
                'min_length' => 25,
                'exclusion_patterns' => [],
            ],
        ]);
    });

    it('preserves non-redactable objects when behavior is set to preserve', function () {
        $redactor = new Redactor;

        // Create circular reference object that can't be JSON serialized
        $object = new \stdClass;
        $object->self = $object;

        $result = $redactor->redact($object);

        expect($result)->toBe($object); // Should preserve original object
    });

    it('removes non-redactable objects when behavior is set to remove', function () {
        // Update the profile config for this test
        config()->set('redactor.profiles.default.non_redactable_object_behavior', 'remove');

        $redactor = new Redactor;

        // Create circular reference object that can't be JSON serialized
        $object = new \stdClass;
        $object->self = $object;

        $result = $redactor->redact($object);

        expect($result)->toBe('__REDACTOR_REMOVE_OBJECT__');
    });

    it('replaces non-redactable objects with empty array when behavior is set to empty_array', function () {
        // Update the profile config for this test
        config()->set('redactor.profiles.default.non_redactable_object_behavior', 'empty_array');

        $redactor = new Redactor;

        // Create circular reference object that can't be JSON serialized
        $object = new \stdClass;
        $object->self = $object;

        $result = $redactor->redact($object);

        expect($result)->toBeArray()
            ->and($result)->toHaveCount(1)
            ->and($result['_redacted'])->toBeTrue();
    });

    it('redacts non-redactable objects with replacement text when behavior is set to redact', function () {
        // Update the profile config for this test
        config()->set('redactor.profiles.default.non_redactable_object_behavior', 'redact');

        $redactor = new Redactor;

        // Create circular reference object that can't be JSON serialized
        $object = new \stdClass;
        $object->self = $object;

        $result = $redactor->redact($object);

        expect($result)->toBeString()
            ->and($result)->toContain('[REDACTED]')
            ->and($result)->toContain('stdClass');
    });

    it('handles complex objects with nested non-redactable content when behavior is redact', function () {
        // Update the profile config for this test
        config()->set('redactor.profiles.default.non_redactable_object_behavior', 'redact');

        $redactor = new Redactor;

        $complexObject = new class
        {
            public function toArray(): array
            {
                $circular = new \stdClass;
                $circular->self = $circular;

                return [
                    'id' => 456,
                    'circular' => $circular, // This will cause issues
                    'name' => 'Test',
                ];
            }
        };

        $result = $redactor->redact($complexObject);

        // The object has a toArray method that works, so it gets processed as an array
        // The circular reference within gets redacted individually
        expect($result)->toBeArray()
            ->and($result['id'])->toBe(456)
            ->and($result['name'])->toBe('Test')
            ->and($result['circular'])->toContain('[REDACTED]')
            ->and($result['_redacted'])->toBeTrue();
    });

    it('handles JsonSerializable objects that return invalid JSON when behavior is redact', function () {
        // Update the profile config for this test
        config()->set('redactor.profiles.default.non_redactable_object_behavior', 'redact');

        $redactor = new Redactor;

        $invalidJsonObject = new class implements \JsonSerializable
        {
            public function jsonSerialize(): string
            {
                // Return invalid JSON string
                return '{invalid json}';
            }
        };

        $result = $redactor->redact($invalidJsonObject);

        // Should fall back to redact behavior since JSON encoding/decoding will fail
        expect($result)->toBeString()
            ->and($result)->toContain('[REDACTED]');
    });

    it('tracks redacted keys when non-redactable object behavior is remove', function () {
        // Update the profile config for this test
        config()->set('redactor.profiles.default.track_redacted_keys', true);
        config()->set('redactor.profiles.default.non_redactable_object_behavior', 'remove');
        config()->set('redactor.profiles.default.blocked_keys', ['password']);

        $redactor = new Redactor;

        // Create circular reference object
        $circular = new \stdClass;
        $circular->self = $circular;

        $data = [
            'good_data' => 'safe_value',
            'password' => 'secret',
            'problematic' => $circular,
        ];

        $result = $redactor->redact($data);

        expect($result)->toBeArray()
            ->and($result)->toHaveKey('good_data')
            ->and($result['good_data'])->toBe('safe_value')
            ->and($result['password'])->toBe('[REDACTED]')
            ->and($result)->not->toHaveKey('problematic') // Should be removed
            ->and($result['_redacted'])->toBeTrue()
            ->and($result)->toHaveKey('_redacted_keys')
            ->and($result['_redacted_keys'])->toContain('password');
    });

    it('handles non-redactable objects within arrays when behavior is empty_array', function () {
        // Update the profile config for this test
        config()->set('redactor.profiles.default.non_redactable_object_behavior', 'empty_array');

        $redactor = new Redactor;

        // Create circular reference object
        $circular = new \stdClass;
        $circular->self = $circular;

        $data = [
            'normal_data' => ['key' => 'value'],
            'problematic' => $circular,
        ];

        $result = $redactor->redact($data);

        expect($result)->toBeArray()
            ->and($result['normal_data'])->toBeArray()
            ->and($result['normal_data']['key'])->toBe('value')
            ->and($result['problematic'])->toBeArray()
            ->and($result['problematic'])->toHaveCount(0) // Empty array behavior
            ->and($result['_redacted'])->toBeTrue();
    });

    it('preserves non-redactable objects by default when behavior is preserve', function () {
        // Update the profile config for this test
        config()->set('redactor.profiles.default.non_redactable_object_behavior', 'preserve');

        $redactor = new Redactor;

        // Create an object that will cause JSON encoding issues
        $problematic = new class
        {
            /** @var resource */
            public $resource;

            public function __construct()
            {
                $this->resource = fopen('php://memory', 'r+');
            }
        };

        $data = ['normal' => 'value', 'problematic' => $problematic];
        $result = $redactor->redact($data);

        expect($result['normal'])->toBe('value')
            ->and($result['problematic'])->toBe($problematic); // Should preserve original
    });

    it('handles deeply nested non-redactable objects when behavior is preserve', function () {
        // Update the profile config for this test
        config()->set('redactor.profiles.default.non_redactable_object_behavior', 'preserve');

        $redactor = new Redactor;

        // Create nested structure with problematic object deep inside
        $circular = new \stdClass;
        $circular->self = $circular;

        $data = [
            'level1' => [
                'level2' => [
                    'normal' => 'value',
                    'problematic' => $circular,
                ],
            ],
        ];

        $result = $redactor->redact($data);

        expect($result['level1']['level2']['normal'])->toBe('value')
            ->and($result['level1']['level2']['problematic'])->toBe($circular); // Should preserve
    });

    it('handles objects that JSON decode to non-array values', function () {
        // Test when JSON decode doesn't return an array
        $problematicObject = new class implements \JsonSerializable
        {
            public function jsonSerialize(): string
            {
                return 'not_an_array_when_decoded';
            }
        };

        $redactor = new Redactor;
        $result = $redactor->redact($problematicObject);

        // Should handle gracefully based on non_redactable_object_behavior (default: preserve)
        expect($result)->toBe($problematicObject);
    });

    it('handles LargeObjectStrategy with scalar values passed directly to handle method', function () {
        // Test the final return $value; line in LargeObjectStrategy that can only be reached
        // by calling handle directly with a scalar value (shouldHandle would never allow this)
        $strategy = new \Kirschbaum\Redactor\Strategies\LargeObjectStrategy;
        $config = \Kirschbaum\Redactor\RedactorConfig::fromConfig('default');
        $context = new \Kirschbaum\Redactor\RedactionContext($config);

        // Call handle directly with scalar values
        expect($strategy->handle('test string', 'test_key', $context))->toBe('test string');
        expect($strategy->handle(123, 'test_key', $context))->toBe(123);
        expect($strategy->handle(12.34, 'test_key', $context))->toBe(12.34);
        expect($strategy->handle(true, 'test_key', $context))->toBe(true);
        expect($strategy->handle(null, 'test_key', $context))->toBe(null);
    });

    it('handles LargeObjectStrategy toArray exception in handle method', function () {
        // Test exception handling in toArray during handle method
        $strategy = new \Kirschbaum\Redactor\Strategies\LargeObjectStrategy;
        $config = \Kirschbaum\Redactor\RedactorConfig::fromConfig('default');
        $context = new \Kirschbaum\Redactor\RedactionContext($config);

        $problematicObject = new class
        {
            public function toArray()
            {
                throw new \Exception('toArray failed in handle');
            }
        };

        // This should trigger the exception catch in handle method
        $result = $strategy->handle($problematicObject, 'test_key', $context);

        expect($result)->toBeArray();
        expect($result)->toHaveKey('_large_object_redacted');
        expect($result['_large_object_redacted'])->toContain('large number of');
    });

    it('handles LargeObjectStrategy JSON encoding exception in handle method', function () {
        // Test JSON encoding exception handling in handle method else branch
        $strategy = new \Kirschbaum\Redactor\Strategies\LargeObjectStrategy;
        $config = \Kirschbaum\Redactor\RedactorConfig::fromConfig('default');
        $context = new \Kirschbaum\Redactor\RedactionContext($config);

        // Create an object without toArray method that will fail JSON encoding
        $problematicObject = new class
        {
            private $resource;

            public function __construct()
            {
                // Create a resource that can't be JSON encoded
                $this->resource = fopen('php://memory', 'w');
            }

            public function __destruct()
            {
                if (is_resource($this->resource)) {
                    fclose($this->resource);
                }
            }
        };

        // Call handle method directly - this should trigger the else branch and JSON exception
        $result = $strategy->handle($problematicObject, 'test_key', $context);

        expect($result)->toBeArray();
        expect($result)->toHaveKey('_large_object_redacted');
        $message = $result['_large_object_redacted'];
        expect($message)->toContain('[REDACTED]');
        expect($message)->toContain('Object');
        expect($message)->toContain('properties');
    });
});
