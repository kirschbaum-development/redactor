<?php

declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | Default Profile
    |--------------------------------------------------------------------------
    |
    | The default profile to use when no specific profile is requested.
    | This should match one of the profile names defined below.
    |
    */

    'default_profile' => env('REDACTOR_DEFAULT_PROFILE', 'default'),

    'scan' => [
        'profile' => env('REDACTOR_SCAN_PROFILE', 'file_scan'),
        'exclude_patterns' => [
            '*.lock',
            '*.min.js',
            'vendor/*',
            'node_modules/*',
        ],
        'max_file_size' => env('REDACTOR_SCAN_MAX_FILE_SIZE', 10_485_760),
    ],

    /*
    |--------------------------------------------------------------------------
    | Redaction Profiles
    |--------------------------------------------------------------------------
    |
    | Define different redaction profiles with their own strategies, patterns,
    | and configurations. Each profile can have a custom set of rules and
    | strategy ordering to suit different use cases.
    |
    */

    'profiles' => [
        /*
        |----------------------------------------------------------------------
        | Default Profile
        |----------------------------------------------------------------------
        |
        | The standard redaction profile suitable for most applications.
        | Provides balanced security and performance.
        |
        */
        'default' => [
            'enabled' => env('REDACTOR_ENABLED', true),

            /*
            | Strategy execution order (array order = execution priority)
            | Strategies are executed in the order listed below.
            */
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\LargeObjectStrategy::class,
                \Kirschbaum\Redactor\Strategies\LargeStringStrategy::class,
                \Kirschbaum\Redactor\Strategies\RegexPatternsStrategy::class,
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],

            'safe_keys' => [
                // Core identifiers (high frequency)
                'id',
                'uuid',
                'user_id',
                'order_id',
                'session_id',
                'request_id',

                // Timestamps & metadata (high frequency)
                'created_at',
                'updated_at',
                'timestamp',

                // Redactor framework keys (highest frequency)
                'level',
                'event',
                'message',
                'trace_id',
                'channel',
                'duration_ms',
                'memory_mb',

                // Controlled block keys
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
                '*token*',  // Matches any key containing 'token'
                '*key*',    // Matches any key containing 'key'
                '*secret*', // Matches any key containing 'secret'
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
            ],

            'patterns' => [
                // Ordered by frequency and performance (most common/fastest first)
                'email' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/',
                'phone_simple' => '/\b\d{3}[.-]?\d{3}[.-]?\d{4}\b/',
                'ssn' => '/\b\d{3}-?\d{2}-?\d{4}\b/',
                'credit_card' => '/\b(?:\d[ -]*?){13,16}\b/',
                'url_with_auth' => '/https?:\/\/[^:\/\s]+:[^@\/\s]+@[^\s]+/',
            ],

            'replacement' => env('REDACTOR_REPLACEMENT', '[REDACTED]'),
            'mark_redacted' => env('REDACTOR_MARK_REDACTED', true),
            'track_redacted_keys' => env('REDACTOR_TRACK_KEYS', false),
            'non_redactable_object_behavior' => env('REDACTOR_OBJECT_BEHAVIOR', 'preserve'),
            'max_value_length' => env('REDACTOR_MAX_VALUE_LENGTH', 5000),
            'redact_large_objects' => env('REDACTOR_LARGE_OBJECTS', true),
            'max_object_size' => env('REDACTOR_MAX_OBJECT_SIZE', 100),

            'shannon_entropy' => [
                'enabled' => env('REDACTOR_SHANNON_ENABLED', true),
                'threshold' => env('REDACTOR_SHANNON_THRESHOLD', 4.8),
                'min_length' => env('REDACTOR_SHANNON_MIN_LENGTH', 25),
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
                    '/^(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE|SHOW|DESCRIBE|EXPLAIN)\s+/i',
                ],
            ],
        ],

        /*
        |----------------------------------------------------------------------
        | Strict Profile
        |----------------------------------------------------------------------
        |
        | High-security profile with aggressive redaction for sensitive
        | environments. More patterns, lower thresholds, stricter rules.
        |
        */
        'strict' => [
            'enabled' => true,

            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\LargeObjectStrategy::class,
                \Kirschbaum\Redactor\Strategies\LargeStringStrategy::class,
                \Kirschbaum\Redactor\Strategies\RegexPatternsStrategy::class,
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],

            // Minimal safe keys for strict environments
            'safe_keys' => [
                'id',
                'uuid',
                'created_at',
                'updated_at',
                'timestamp',
                'level',
                'event',
                'message',
            ],

            // Extended blocked keys
            'blocked_keys' => [
                'password',
                'secret',
                '*token*',  // Matches any key containing 'token'
                '*key*',    // Matches any key containing 'key'
                '*secret*', // Matches any key containing 'secret'
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
                'phone',
                'address',
                'user_agent',
                'ip',
                'name',
                'username',
            ],

            'patterns' => [
                'email' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/',
                'phone' => '/\+?[\d\s\-\(\)]{7,15}/',
                'ssn' => '/\b\d{3}-?\d{2}-?\d{4}\b/',
                'credit_card' => '/\b(?:\d[ -]*?){13,16}\b/',
                'url_with_auth' => '/https?:\/\/[^:\/\s]+:[^@\/\s]+@[^\s]+/',
                'ipv4' => '/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/',
                'uuid' => '/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i',
                'jwt' => '/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/',
            ],

            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => true,
            'non_redactable_object_behavior' => 'redact',
            'max_value_length' => 1000, // More aggressive
            'redact_large_objects' => true,
            'max_object_size' => 25, // Smaller objects

            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.0, // Lower threshold = more sensitive
                'min_length' => 15, // Shorter minimum length
                'exclusion_patterns' => [
                    '/^https?:\/\//',
                    '/^\d{4}-\d{2}-\d{2}/',
                ],
            ],
        ],

        /*
        |----------------------------------------------------------------------
        | File Scan Profile
        |----------------------------------------------------------------------
        |
        | Optimized profile for scanning files with plain text content.
        | Focuses on pattern matching and entropy detection rather than
        | key-based strategies. Ideal for file scanning operations.
        |
        */
        'file_scan' => [
            'enabled' => true,

            /*
            | Only strategies that work well with plain text content
            */
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\RegexPatternsStrategy::class,
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],

            // No key-based strategies for file scanning
            'safe_keys' => [],
            'blocked_keys' => [],

            // Enhanced patterns for file content detection
            'patterns' => [
                'email' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/',
                'phone_simple' => '/\b\d{3}[.-]?\d{3}[.-]?\d{4}\b/',
                'ssn' => '/\b\d{3}-?\d{2}-?\d{4}\b/',
                'credit_card' => '/\b(?:\d[ -]*?){13,16}\b/',
                'url_with_auth' => '/https?:\/\/[^:\/\s]+:[^@\/\s]+@[^\s]+/',
                'api_key_stripe' => '/sk_(?:test_|live_)[a-zA-Z0-9]{24,}/',
                'api_key_generic' => '/(?:api[_-]?key|access[_-]?token|secret[_-]?key)[\s=:]+[a-zA-Z0-9_-]{16,}/',
                'jwt_token' => '/eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+/',
                'base64_key' => '/(?:key|token|secret)[\s=:]+[A-Za-z0-9+\/]{32,}={0,2}/',
                'aws_access_key' => '/AKIA[0-9A-Z]{16}/',
                'aws_secret_key' => '/[0-9a-zA-Z\/+]{40}/',
                'github_token' => '/gh[pousr]_[A-Za-z0-9_]{36}/',
                'password_assignment' => '/password[\s=:]+[^\s\n\r]+/',
            ],

            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,

            // Tuned Shannon entropy for file scanning
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.8, // Standard threshold
                'min_length' => 25,  // Standard minimum length
                'exclusion_patterns' => [
                    '/^https?:\/\//',
                    '/^[\/\\\\].+[\/\\\\]/',
                    '/^\d{4}-\d{2}-\d{2}/',
                    '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i',
                    '/^\s*$/',
                    '/^Mozilla\/\d\.\d|^[A-Za-z]+\/\d+\.\d+|AppleWebKit|Chrome|Safari|Firefox|Opera|Edge/',
                    '/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/',
                    '/^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i',
                    '/^(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE|SHOW|DESCRIBE|EXPLAIN)\s+/i',
                    '/^[a-zA-Z]{1,15}$/', // Exclude short words and common terms
                    '/^[A-Za-z]+\s+[A-Za-z]+(\s+[A-Za-z]+)*$/', // Exclude normal sentences with words
                    '/^\d+$/', // Exclude pure numbers
                    '/^[A-Z]{2,}$/', // Exclude acronyms
                    '/^[a-z]{2,}$/', // Exclude lowercase words
                ],
            ],
        ],

        /*
        |----------------------------------------------------------------------
        | Performance Profile
        |----------------------------------------------------------------------
        |
        | Optimized for high-throughput environments. Fewer patterns,
        | higher thresholds, focus on speed over comprehensive redaction.
        |
        */
        'performance' => [
            'enabled' => true,

            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
                // Skip large object/string checks for performance
                \Kirschbaum\Redactor\Strategies\RegexPatternsStrategy::class,
                // Disable shannon entropy for performance
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
                '*token*',  // Matches any key containing 'token'
                '*key*',    // Matches any key containing 'key'
                'authorization',
                'private_key',
                'client_secret',
            ],

            // Minimal, fast patterns only
            'patterns' => [
                'email' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/',
                'simple_token' => '/^[A-Za-z0-9]{32,}$/',
            ],

            'replacement' => '[REDACTED]',
            'mark_redacted' => false, // Skip for performance
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null, // Disable
            'redact_large_objects' => false, // Disable
            'max_object_size' => null,

            'shannon_entropy' => [
                'enabled' => false, // Disabled for performance
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Custom Strategy Classes
    |--------------------------------------------------------------------------
    |
    | Register custom strategy classes that can be used in profiles.
    | These should implement RedactionStrategyInterface.
    |
    */

    'custom_strategies' => [
        // Example:
        // 'my_custom_strategy' => \App\Redaction\MyCustomStrategy::class,
    ],
];
