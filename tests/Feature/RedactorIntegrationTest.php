<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Redactor;

describe('Redactor Integration Tests', function () {
    it('integrates with Laravel Log and redacts context', function () {
        // Set up completely explicit profile for this specific test
        config()->set('redactor.default_profile', 'integration_test');
        config()->set('redactor.profiles.integration_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\RegexPatternsStrategy::class,
            ],
            'safe_keys' => ['user_id'],
            'blocked_keys' => ['password', 'secret'],
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

        $sensitiveContext = [
            'user_id' => 12345,
            'password' => 'secret123',
            'user_email' => 'user@example.com', // Should be redacted by regex
            'secret' => 'hidden',
            'normal_data' => 'visible',
        ];

        // Create the redactor and manually test redaction
        $redactor = new Redactor;
        $redactedContext = $redactor->redact($sensitiveContext);

        // Verify the redaction works correctly
        expect($redactedContext['user_id'])->toBe(12345) // Safe key
            ->and($redactedContext['password'])->toBe('[REDACTED]') // Blocked key
            ->and($redactedContext['user_email'])->toBe('[REDACTED]') // Regex pattern
            ->and($redactedContext['secret'])->toBe('[REDACTED]') // Blocked key
            ->and($redactedContext['normal_data'])->toBe('visible') // Normal data
            ->and($redactedContext['_redacted'])->toBeTrue();
    });
});

describe('Redactor Real-world Scenario Tests', function () {
    it('handles realistic user registration context', function () {
        // Explicit profile for user registration test
        config()->set('redactor.default_profile', 'user_registration_test');
        config()->set('redactor.profiles.user_registration_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\RegexPatternsStrategy::class,
            ],
            'safe_keys' => ['id', 'user_id', 'created_at', 'updated_at'],
            'blocked_keys' => ['email', 'ssn', 'password'],
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
                'threshold' => 4.0,
                'min_length' => 20,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'user_id' => 12345,
            'email' => 'john.doe@example.com',
            'password' => 'MySecretPassword123!',
            'ssn' => '123-45-6789',
            'created_at' => '2023-12-25T15:30:45Z',
            'ip_address' => '192.168.1.100',
            'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'registration_source' => 'web',
        ];

        $result = $redactor->redact($context);

        expect($result['user_id'])->toBe(12345) // Safe key
            ->and($result['email'])->toBe('[REDACTED]') // Blocked key
            ->and($result['password'])->toBe('[REDACTED]') // Blocked key
            ->and($result['ssn'])->toBe('[REDACTED]') // Blocked key
            ->and($result['created_at'])->toBe('2023-12-25T15:30:45Z') // Safe key
            ->and($result['ip_address'])->toBe('192.168.1.100') // Not redacted
            ->and($result['user_agent'])->toBe('Mozilla/5.0 (Windows NT 10.0; Win64; x64)') // Not redacted
            ->and($result['registration_source'])->toBe('web') // Not redacted
            ->and($result['_redacted'])->toBeTrue();
    });

    it('handles API request context with tokens', function () {
        // Explicit profile for API token test with Shannon entropy enabled
        config()->set('redactor.default_profile', 'api_token_test');
        config()->set('redactor.profiles.api_token_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            'safe_keys' => ['request_id', 'user_id', 'endpoint', 'method', 'created_at'],
            'blocked_keys' => ['api_key'],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.0,
                'min_length' => 20,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'request_id' => 'req_123456',
            'user_id' => 78901,
            'api_key' => 'sk-1234567890abcdef1234567890abcdef12345678',
            'stripe_token' => 'tok_1ABCDEfghijklmnop2QRSTUv', // High entropy
            'jwt_payload' => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
            'endpoint' => '/api/v1/users',
            'method' => 'POST',
            'created_at' => '2023-12-25T16:00:00Z',
        ];

        $result = $redactor->redact($context);

        expect($result['request_id'])->toBe('req_123456') // Safe key
            ->and($result['user_id'])->toBe(78901) // Safe key
            ->and($result['api_key'])->toBe('[REDACTED]') // Blocked key
            ->and($result['stripe_token'])->toBe('[REDACTED]') // High entropy
            ->and($result['jwt_payload'])->toBe('[REDACTED]') // High entropy
            ->and($result['endpoint'])->toBe('/api/v1/users') // Safe key
            ->and($result['method'])->toBe('POST') // Safe key
            ->and($result['created_at'])->toBe('2023-12-25T16:00:00Z') // Safe key
            ->and($result['_redacted'])->toBeTrue();
    });

    it('handles complex e-commerce order context', function () {
        // Explicit profile for e-commerce test
        config()->set('redactor.default_profile', 'ecommerce_test');
        config()->set('redactor.profiles.ecommerce_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            'safe_keys' => ['order_id', 'user_id', 'created_at', 'address', 'city', 'name', 'price', 'amount', 'payment_id'],
            'blocked_keys' => ['email', 'ssn'],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.0,
                'min_length' => 20,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'order_id' => 'order_789',
            'user_id' => 456,
            'billing' => [
                'email' => 'customer@example.com',
                'ssn' => '987-65-4321',
                'address' => '123 Main St',
                'city' => 'New York',
            ],
            'payment' => [
                'stripe_token' => 'sk-test_4eC39HqLyjWDarjtT1zdp7dc',
                'payment_id' => 'pi_1234567890abcdef',
                'amount' => 29.99,
            ],
            'items' => [
                ['name' => 'Product A', 'price' => 19.99],
                ['name' => 'Product B', 'price' => 9.99],
            ],
            'created_at' => '2023-12-25T17:00:00Z',
        ];

        $result = $redactor->redact($context);

        expect($result['order_id'])->toBe('order_789') // Safe key
            ->and($result['user_id'])->toBe(456) // Safe key
            ->and($result['billing']['email'])->toBe('[REDACTED]') // Blocked key
            ->and($result['billing']['ssn'])->toBe('[REDACTED]') // Blocked key
            ->and($result['billing']['address'])->toBe('123 Main St') // Safe key
            ->and($result['billing']['city'])->toBe('New York') // Safe key
            ->and($result['payment']['stripe_token'])->toBe('[REDACTED]') // High entropy
            ->and($result['payment']['payment_id'])->toBe('pi_1234567890abcdef') // Safe key
            ->and($result['payment']['amount'])->toBe(29.99) // Safe key
            ->and($result['items'][0]['name'])->toBe('Product A') // Safe key
            ->and($result['items'][0]['price'])->toBe(19.99) // Safe key
            ->and($result['created_at'])->toBe('2023-12-25T17:00:00Z') // Safe key
            ->and($result['_redacted'])->toBeTrue();
    });

    it('handles logging context with database queries and errors', function () {
        // Explicit profile for logging test
        config()->set('redactor.default_profile', 'logging_test');
        config()->set('redactor.profiles.logging_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            'safe_keys' => ['user_id', 'query', 'level', 'message', 'file', 'line', 'duration_ms'],
            'blocked_keys' => ['password', 'api_key'],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.0,
                'min_length' => 20,
                'exclusion_patterns' => [
                    '/^(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE|SHOW|DESCRIBE|EXPLAIN)\s+/i',
                ],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'user_id' => 123,
            'query' => 'SELECT * FROM users WHERE email = ?',
            'bindings' => ['john@example.com'],
            'level' => 'error',
            'message' => 'Database connection failed',
            'exception' => [
                'class' => 'PDOException',
                'message' => 'Connection refused',
                'file' => '/app/database/Connection.php',
                'line' => 45,
            ],
            'api_key' => 'sk-live_abcdef1234567890',
            'session_token' => 'sess_9f8e7d6c5b4a3210fedcba0987654321',
            'duration_ms' => 1250,
        ];

        $result = $redactor->redact($context);

        expect($result['user_id'])->toBe(123) // Safe key
            ->and($result['query'])->toBe('SELECT * FROM users WHERE email = ?') // Safe key (SQL exclusion pattern)
            ->and($result['bindings'][0])->toBe('john@example.com') // Not redacted (no email pattern)
            ->and($result['level'])->toBe('error') // Safe key
            ->and($result['message'])->toBe('Database connection failed') // Safe key
            ->and($result['exception']['class'])->toBe('PDOException') // Not redacted
            ->and($result['exception']['message'])->toBe('Connection refused') // Not redacted
            ->and($result['exception']['file'])->toBe('/app/database/Connection.php') // Not redacted
            ->and($result['exception']['line'])->toBe(45) // Not redacted
            ->and($result['api_key'])->toBe('[REDACTED]') // Blocked key
            ->and($result['session_token'])->toBe('[REDACTED]') // High entropy
            ->and($result['duration_ms'])->toBe(1250) // Safe key
            ->and($result['_redacted'])->toBeTrue();
    });
});
