<?php

declare(strict_types=1);
use Kirschbaum\Redactor\Strategies\BlockedKeysStrategy;
use Kirschbaum\Redactor\Strategies\LargeObjectStrategy;
use Kirschbaum\Redactor\Strategies\LargeStringStrategy;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;
use Kirschbaum\Redactor\Strategies\SafeKeysStrategy;
use Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy;

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

        /*
        | Glob patterns, matched against both the file's basename and its path
        | relative to each scanned directory. A pattern ending in '/*' also
        | prunes that directory during the walk rather than filtering its
        | files one at a time.
        */
        'exclude_patterns' => [
            '*.lock',
            '*.min.js',
            '*.map',
            'vendor/*',
            'node_modules/*',
            'storage/framework/*',
            'public/build/*',
        ],

        'max_file_size' => env('REDACTOR_SCAN_MAX_FILE_SIZE', 10_485_760),

        // Skip images, archives and compiled artefacts: scanning them
        // produces nothing but entropy false positives.
        'skip_binary' => env('REDACTOR_SCAN_SKIP_BINARY', true),

        // Skip anything git is already ignoring.
        'respect_gitignore' => env('REDACTOR_SCAN_RESPECT_GITIGNORE', true),

        /*
        | Accepted findings, so CI fails on new secrets rather than on known
        | ones. Generate with:
        |
        |     php artisan redactor:scan --update-baseline
        |
        | The file stores hashed fingerprints, never the secrets themselves.
        */
        'baseline' => env('REDACTOR_SCAN_BASELINE', base_path('.redactor-baseline.json')),
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
                SafeKeysStrategy::class,
                BlockedKeysStrategy::class,
                LargeObjectStrategy::class,
                LargeStringStrategy::class,
                RegexPatternsStrategy::class,
                ShannonEntropyStrategy::class,
            ],

            /*
            | Keys whose contents are safe by construction: identifiers,
            | timestamps and enumerations. Everything under a safe key is
            | preserved as-is, nested structures included, so a free-text
            | field must never be listed here however harmless its name.
            */
            'safe_keys' => [
                // Core identifiers (high frequency)
                'id',
                'uuid',
                'user_id',
                'order_id',
                'request_id',
                'trace_id',

                // Timestamps & metadata (high frequency)
                'created_at',
                'updated_at',
                'timestamp',

                // Log framework keys (highest frequency)
                'level',
                'event',
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

                // Enumerations and fixed vocabularies
                'type',
                'method',
                'operation',
                'action',
                'version',
                'platform',
                'environment',

                /*
                | Deliberately NOT safe, though earlier versions listed them:
                |
                |   message, title    free text, the commonest PII carrier
                |   url, path         query strings carry tokens and emails
                |   ip, user_agent    personal data under GDPR
                |   source, target    free-form, frequently addresses or paths
                |   session_id        was simultaneously listed under
                |                     blocked_keys; safe_keys won, so it was
                |                     never redacted
                */
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

            /*
            | Rules are applied in the order listed. url_with_auth must come
            | before email: the email rule would otherwise match "user@host"
            | inside a credential URL and take the hostname with it.
            */
            'patterns' => [
                'url_with_auth' => [
                    // Replace the credentials, keep the host and path.
                    'pattern' => '/(https?:\/\/[^:\/\s]+:)([^@\/\s]+)(@)/',
                    'capture' => 2,
                ],
                'email' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/',
                'phone_simple' => '/\b\d{3}[.-]?\d{3}[.-]?\d{4}\b/',
                'ssn' => [
                    'pattern' => '/\b\d{3}-?\d{2}-?\d{4}\b/',
                    // Rejects the never-issued area/group/serial values, which
                    // is most of what matches this shape by accident.
                    'validator' => 'ssn',
                ],
                'credit_card' => [
                    'pattern' => '/\b(?:\d[ -]*?){13,16}\b/',
                    // Without the Luhn check this matches any 13-16 digit run:
                    // order numbers, tracking codes, concatenated timestamps.
                    'validator' => 'luhn',
                    'mode' => 'partial',
                    'keep' => 4,
                ],
                'iban' => [
                    'pattern' => '/\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/',
                    'validator' => 'iban',
                ],
            ],

            'replacement' => env('REDACTOR_REPLACEMENT', '[REDACTED]'),
            'mark_redacted' => env('REDACTOR_MARK_REDACTED', true),
            'track_redacted_keys' => env('REDACTOR_TRACK_KEYS', false),
            'non_redactable_object_behavior' => env('REDACTOR_OBJECT_BEHAVIOR', 'preserve'),
            'max_value_length' => env('REDACTOR_MAX_VALUE_LENGTH', 5000),
            'redact_large_objects' => env('REDACTOR_LARGE_OBJECTS', true),
            'max_object_size' => env('REDACTOR_MAX_OBJECT_SIZE', 100),

            /*
            | How many levels deep the redactor will walk before replacing the
            | rest of the subtree. Guards against cyclic and pathologically
            | nested payloads.
            */
            'max_depth' => env('REDACTOR_MAX_DEPTH', 32),

            'shannon_entropy' => [
                'enabled' => env('REDACTOR_SHANNON_ENABLED', true),
                'threshold' => env('REDACTOR_SHANNON_THRESHOLD', 4.8),
                'min_length' => env('REDACTOR_SHANNON_MIN_LENGTH', 25),

                /*
                | Per-alphabet thresholds. A hex digest cannot exceed 4.0 bits
                | per character because it only has 16 symbols to draw on, so
                | judging it against a base64 threshold guarantees a miss;
                | judging base64 against a hex threshold guarantees false
                | positives. Remove this block to judge every token against
                | the single `threshold` above.
                */
                'charset_thresholds' => [
                    'hex' => 3.0,        // max possible 4.0
                    'base64' => 4.5,     // max possible 6.0
                    'base64url' => 4.5,  // max possible 6.0
                ],

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
                SafeKeysStrategy::class,
                BlockedKeysStrategy::class,
                LargeObjectStrategy::class,
                LargeStringStrategy::class,
                RegexPatternsStrategy::class,
                ShannonEntropyStrategy::class,
            ],

            // Minimal safe keys for strict environments. 'message' is
            // excluded: it is free text, which is exactly what strict mode
            // exists to inspect.
            'safe_keys' => [
                'id',
                'uuid',
                'created_at',
                'updated_at',
                'timestamp',
                'level',
                'event',
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
                'url_with_auth' => [
                    'pattern' => '/(https?:\/\/[^:\/\s]+:)([^@\/\s]+)(@)/',
                    'capture' => 2,
                ],
                'email' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/',
                'phone' => '/\+?[\d\s\-\(\)]{7,15}/',
                'ssn' => ['pattern' => '/\b\d{3}-?\d{2}-?\d{4}\b/', 'validator' => 'ssn'],
                'credit_card' => ['pattern' => '/\b(?:\d[ -]*?){13,16}\b/', 'validator' => 'luhn'],
                'iban' => ['pattern' => '/\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/', 'validator' => 'iban'],
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
            'max_depth' => 16, // Shallower walk for stricter environments

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
                RegexPatternsStrategy::class,
                ShannonEntropyStrategy::class,
            ],

            // No key-based strategies for file scanning
            'safe_keys' => [],
            'blocked_keys' => [],

            /*
            | Patterns for file content detection.
            |
            | Rules that need surrounding context to match confidently declare
            | a `capture` group, so the label survives and only the secret is
            | replaced: "aws_secret_access_key = [REDACTED]", not "[REDACTED]".
            */
            'patterns' => [
                'url_with_auth' => [
                    // Replace the credentials, keep the host and path. Must
                    // precede 'email', which would otherwise match "user@host"
                    // inside the credential and take the hostname with it.
                    'pattern' => '/(https?:\/\/[^:\/\s]+:)([^@\/\s]+)(@)/',
                    'capture' => 2,
                ],

                'email' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/',
                'phone_simple' => '/\b\d{3}[.-]?\d{3}[.-]?\d{4}\b/',
                'ssn' => [
                    'pattern' => '/\b\d{3}-?\d{2}-?\d{4}\b/',
                    'validator' => 'ssn',
                ],

                'credit_card' => [
                    'pattern' => '/\b(?:\d[ -]*?){13,16}\b/',
                    'validator' => 'luhn',
                    'mode' => 'partial',
                    'keep' => 4,
                ],

                'api_key_stripe' => '/sk_(?:test_|live_)[a-zA-Z0-9]{24,}/',
                'jwt_token' => '/eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+/',
                'aws_access_key' => '/\bAKIA[0-9A-Z]{16}\b/',
                'github_token' => '/\bgh[pousr]_[A-Za-z0-9_]{36}\b/',

                'api_key_generic' => [
                    'pattern' => '/(?:api[_-]?key|access[_-]?token|secret[_-]?key)([\s=:]+["\']?)([a-zA-Z0-9_\/+-]{16,})/i',
                    'capture' => 2,
                ],

                /*
                | Was '/[0-9a-zA-Z\/+]{40}/', which matches any 40-character
                | alphanumeric run: every SHA-1 digest, every base64 chunk,
                | every minified identifier. AWS secret keys are now only
                | reported next to something that names them.
                */
                'aws_secret_key' => [
                    'pattern' => '/(aws[_\-. ]?(?:secret[_\-. ]?)?access[_\-. ]?key[_\-. ]?(?:id)?["\']?[\s=:]+["\']?)([0-9a-zA-Z\/+]{40})/i',
                    'capture' => 2,
                ],

                'base64_key' => [
                    'pattern' => '/(?:key|token|secret)([\s=:]+["\']?)([A-Za-z0-9+\/]{32,}={0,2})/i',
                    'capture' => 2,
                ],

                'password_assignment' => [
                    // Keep the "password=" label so the finding is readable.
                    'pattern' => '/(password["\']?[\s=:]+["\']?)([^\s\n\r"\']+)/i',
                    'capture' => 2,
                ],
            ],

            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'max_depth' => 32,

            // Tuned Shannon entropy for file scanning
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.8, // Standard threshold
                'min_length' => 25,  // Standard minimum length
                'charset_thresholds' => [
                    'hex' => 3.0,
                    'base64' => 4.5,
                    'base64url' => 4.5,
                ],
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
                SafeKeysStrategy::class,
                BlockedKeysStrategy::class,
                // Skip large object/string checks for performance
                RegexPatternsStrategy::class,
                // Disable shannon entropy for performance
            ],

            // Same rule as the default profile: identifiers and enumerations
            // only, never free text.
            'safe_keys' => [
                'id',
                'uuid',
                'user_id',
                'order_id',
                'request_id',
                'trace_id',
                'created_at',
                'updated_at',
                'timestamp',
                'level',
                'event',
                'channel',
                'duration_ms',
                'memory_mb',
                'controlled_block',
                'controlled_block_id',
                'attempt',
                'status',
                'breaker_tripped',
                'uncaught',
                'type',
                'method',
                'operation',
                'action',
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
            'max_depth' => 16,

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
