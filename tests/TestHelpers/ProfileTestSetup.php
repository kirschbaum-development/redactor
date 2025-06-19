<?php

declare(strict_types=1);

namespace Tests\TestHelpers;

class ProfileTestSetup
{
    /**
     * Set up a basic default profile configuration for tests
     */
    public static function setupBasicProfile(): void
    {
        config()->set('redactor.default_profile', 'default');
        config()->set('redactor.profiles.default', [
            'enabled' => true,
            'strategies' => [
                'safe_keys' => ['priority' => 1],
                'blocked_keys' => ['priority' => 2],
                'large_object' => ['priority' => 3],
                'large_string' => ['priority' => 4],
                'regex_patterns' => ['priority' => 5],
                'shannon_entropy' => ['priority' => 6],
            ],
            'safe_keys' => [
                'id',
                'uuid',
                'user_id',
                'order_id',
                'session_id',
                'request_id',
                'created_at',
                'updated_at',
                'timestamp',
                'level',
                'event',
                'message',
                'trace_id',
                'channel',
                'duration_ms',
                'memory_mb',
                'controlled_block',
                'controlled_block_id',
                'attempt',
                'status',
                'breaker_tripped',
                'uncaught',
                'title',
                'type',
                'method',
                'path',
                'url',
                'ip',
                'user_agent',
                'operation',
                'action',
                'source',
                'target',
                'version',
                'platform',
                'environment',
            ],
            'blocked_keys' => [
                'password',
                'secret',
                'token',
                'api_key',
                'authorization',
                'auth_token',
                'bearer_token',
                'access_token',
                'refresh_token',
                'private_key',
                'client_secret',
                'full_name',
                'first_name',
                'last_name',
                'email',
                'ssn',
                'ein',
                'social_security_number',
                'tax_id',
                'credit_card',
                'card_number',
                'cvv',
                'pin',
            ],
            'patterns' => [
                'email' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/',
                'phone_simple' => '/\b\d{3}[.-]?\d{3}[.-]?\d{4}\b/',
                'ssn' => '/\b\d{3}-?\d{2}-?\d{4}\b/',
                'credit_card' => '/\b(?:\d[ -]*?){13,16}\b/',
                'url_with_auth' => '/https?:\/\/[^:\/\s]+:[^@\/\s]+@[^\s]+/',
            ],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => 5000,
            'redact_large_objects' => true,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.8,
                'min_length' => 25,
                'exclusion_patterns' => [
                    '/^https?:\/\//',
                    '/^[\/\\\\].+[\/\\\\]/',
                    '/^\d{4}-\d{2}-\d{2}/',
                    '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i',
                    '/^[0-9a-f]+$/i',
                    '/^\s*$/',
                    '/^Mozilla\/\d\.\d|^[A-Za-z]+\/\d+\.\d+|AppleWebKit|Chrome|Safari|Firefox|Opera|Edge/',
                    '/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/',
                    '/^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i',
                    '/^(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE|SHOW|DESCRIBE|EXPLAIN)\s+/i/',
                ],
            ],
        ]);
    }

    /**
     * Set up profile configuration that mimics the old flat config for backward compatibility
     */
    public static function setupLegacyCompatibleProfile(): void
    {
        self::setupBasicProfile();

        // Override with the old test values that many tests expect
        config()->set('redactor.profiles.default.safe_keys', [
            'id',
            'uuid',
            'user_id',
            'order_id',
            'session_id',
            'request_id',
            'created_at',
            'updated_at',
            'timestamp',
            'level',
            'event',
            'message',
            'trace_id',
            'channel',
            'duration_ms',
            'memory_mb',
            'controlled_block',
            'controlled_block_id',
            'attempt',
            'status',
            'breaker_tripped',
            'uncaught',
            'title',
            'type',
            'method',
            'path',
            'url',
            'ip',
            'user_agent',
            'operation',
            'action',
            'source',
            'target',
            'version',
            'platform',
            'environment',
        ]);

        config()->set('redactor.profiles.default.blocked_keys', [
            'password',
            'secret',
            'token',
            'api_key',
            'authorization',
            'auth_token',
            'bearer_token',
            'access_token',
            'refresh_token',
            'session_id',
            'private_key',
            'client_secret',
            'full_name',
            'first_name',
            'last_name',
            'email',
            'ssn',
            'ein',
            'social_security_number',
            'tax_id',
            'credit_card',
            'card_number',
            'cvv',
            'pin',
        ]);
    }

    /**
     * Clear all redactor configuration
     */
    public static function clearConfig(): void
    {
        config()->set('redactor', []);
    }
}
