<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Redactor;

describe('Redactor Mixed Input Types Tests', function () {
    beforeEach(function () {
        // Set up profile-based configuration
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
            'safe_keys' => ['id', 'user_id'],
            'blocked_keys' => ['password', 'secret'],
            'patterns' => [
                'email' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/',
            ],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => true,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.0,
                'min_length' => 20,
                'exclusion_patterns' => [],
            ],
        ]);
    });

    it('handles string input with email pattern redaction', function () {
        $redactor = new Redactor;

        $email = 'user@example.com';
        $result = $redactor->redact($email);

        expect($result)->toBe('[REDACTED]');
    });

    it('handles string input without redaction needed', function () {
        $redactor = new Redactor;

        $normalString = 'Hello World';
        $result = $redactor->redact($normalString);

        expect($result)->toBe('Hello World');
    });

    it('handles string input with high entropy redaction', function () {
        $redactor = new Redactor;

        // High entropy string over minimum length
        $highEntropyString = 'sk-1234567890abcdef1234567890abcdef12345678';
        $result = $redactor->redact($highEntropyString);

        expect($result)->toBe('[REDACTED]');
    });

    it('handles object input with toArray method', function () {
        $redactor = new Redactor;

        $object = new class
        {
            public function toArray(): array
            {
                return [
                    'id' => 123,
                    'password' => 'secret123',
                    'email' => 'test@example.com',
                ];
            }
        };

        $result = $redactor->redact($object);

        expect($result)->toBeArray()
            ->and($result['id'])->toBe(123) // Safe key
            ->and($result['password'])->toBe('[REDACTED]') // Blocked key
            ->and($result['email'])->toBe('[REDACTED]') // Regex pattern
            ->and($result['_redacted'])->toBeTrue();
    });

    it('handles object input without toArray method via JSON serialization', function () {
        $redactor = new Redactor;

        $object = new \stdClass;
        $object->id = 456;
        $object->password = 'secret456';
        $object->email = 'json@example.com';

        $result = $redactor->redact($object);

        expect($result)->toBeArray()
            ->and($result['id'])->toBe(456) // Safe key
            ->and($result['password'])->toBe('[REDACTED]') // Blocked key
            ->and($result['email'])->toBe('[REDACTED]') // Regex pattern
            ->and($result['_redacted'])->toBeTrue();
    });

    it('handles non-serializable object based on behavior config', function () {
        // Update the profile config for this test
        config()->set('redactor.profiles.default.non_redactable_object_behavior', 'preserve');

        $redactor = new Redactor;

        // Create circular reference object that can't be JSON serialized
        $object = new \stdClass;
        $object->self = $object;

        $result = $redactor->redact($object);

        expect($result)->toBe($object); // Should preserve original object
    });

    it('handles non-serializable object with remove behavior', function () {
        // Update the profile config for this test
        config()->set('redactor.profiles.default.non_redactable_object_behavior', 'remove');

        $redactor = new Redactor;

        // Create circular reference object that can't be JSON serialized
        $object = new \stdClass;
        $object->self = $object;

        $result = $redactor->redact($object);

        expect($result)->toBe('__REDACTOR_REMOVE_OBJECT__');
    });

    it('handles non-serializable object with empty_array behavior', function () {
        // Update the profile config for this test
        config()->set('redactor.profiles.default.non_redactable_object_behavior', 'empty_array');

        $redactor = new Redactor;

        // Create circular reference object that can't be JSON serialized
        $object = new \stdClass;
        $object->self = $object;

        $result = $redactor->redact($object);

        // The empty array behavior still sets wasRedacted=true, so metadata is added
        expect($result)->toBeArray()
            ->and($result)->toHaveCount(1)
            ->and($result['_redacted'])->toBeTrue();
    });

    it('handles non-serializable object with redact behavior', function () {
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

    it('handles integer input unchanged', function () {
        $redactor = new Redactor;

        $integer = 12345;
        $result = $redactor->redact($integer);

        expect($result)->toBe(12345);
    });

    it('handles float input unchanged', function () {
        $redactor = new Redactor;

        $float = 123.45;
        $result = $redactor->redact($float);

        expect($result)->toBe(123.45);
    });

    it('handles boolean input unchanged', function () {
        $redactor = new Redactor;

        $boolean = true;
        $result = $redactor->redact($boolean);

        expect($result)->toBe(true);
    });

    it('handles null input unchanged', function () {
        $redactor = new Redactor;

        $null = null;
        $result = $redactor->redact($null);

        expect($result)->toBeNull();
    });

    it('handles array input with metadata (existing functionality)', function () {
        // Update the profile config for this test
        config()->set('redactor.profiles.default.track_redacted_keys', true);

        $redactor = new Redactor;

        $array = [
            'id' => 789,
            'password' => 'secret789',
            'email' => 'array@example.com',
        ];

        $result = $redactor->redact($array);

        expect($result)->toBeArray()
            ->and($result['id'])->toBe(789) // Safe key
            ->and($result['password'])->toBe('[REDACTED]') // Blocked key
            ->and($result['email'])->toBe('[REDACTED]') // Regex pattern
            ->and($result['_redacted'])->toBeTrue()
            ->and($result)->toHaveKey('_redacted_keys')
            ->and($result['_redacted_keys'])->toContain('password');
    });

    it('does not add metadata to non-array results', function () {
        $redactor = new Redactor;

        $email = 'user@example.com';
        $result = $redactor->redact($email);

        // Should be redacted string, not array with metadata
        expect($result)->toBe('[REDACTED]')
            ->and($result)->not->toBeArray();
    });

    it('handles nested mixed types within arrays', function () {
        $redactor = new Redactor;

        $object = new \stdClass;
        $object->secret = 'hidden';
        $object->id = 999;

        $complexArray = [
            'string' => 'test@example.com',
            'object' => $object,
            'number' => 42,
            'nested' => [
                'password' => 'nested_secret',
                'safe_id' => 123,
            ],
        ];

        $result = $redactor->redact($complexArray);

        expect($result)->toBeArray()
            ->and($result['string'])->toBe('[REDACTED]') // Email pattern
            ->and($result['object'])->toBeArray()
            ->and($result['object']['secret'])->toBe('[REDACTED]') // Blocked key
            ->and($result['object']['id'])->toBe(999) // Safe key
            ->and($result['number'])->toBe(42) // Unchanged
            ->and($result['nested'])->toBeArray()
            ->and($result['nested']['password'])->toBe('[REDACTED]') // Blocked key
            ->and($result['nested']['safe_id'])->toBe(123) // Not in safe keys config
            ->and($result['_redacted'])->toBeTrue();
    });
});

describe('Redactor Nested Structure Tests', function () {
    beforeEach(function () {
        // Set up profile-based configuration for nested tests
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
            'safe_keys' => ['id', 'name'],
            'blocked_keys' => ['password', 'secret'],
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

    it('handles nested arrays and objects recursively', function () {
        $redactor = new Redactor;

        $context = [
            'user' => [
                'id' => 123,
                'name' => 'John Doe',
                'password' => 'secret123',
                'preferences' => [
                    'id' => 456,
                    'secret' => 'hidden_value',
                    'theme' => 'dark',
                ],
            ],
            'admin' => [
                'name' => 'Admin User',
                'password' => 'admin_secret',
            ],
        ];

        $result = $redactor->redact($context);

        expect($result['user']['id'])->toBe(123)
            ->and($result['user']['name'])->toBe('John Doe')
            ->and($result['user']['password'])->toBe('[REDACTED]')
            ->and($result['user']['preferences']['id'])->toBe(456)
            ->and($result['user']['preferences']['secret'])->toBe('[REDACTED]')
            ->and($result['user']['preferences']['theme'])->toBe('dark')
            ->and($result['admin']['name'])->toBe('Admin User')
            ->and($result['admin']['password'])->toBe('[REDACTED]')
            ->and($result['_redacted'])->toBeTrue();
    });
});
