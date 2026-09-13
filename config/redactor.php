<?php

declare(strict_types=1);
use Kirschbaum\Redactor\Strategies\BlockedKeysStrategy;
use Kirschbaum\Redactor\Strategies\LargeObjectStrategy;
use Kirschbaum\Redactor\Strategies\LargeStringStrategy;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;
use Kirschbaum\Redactor\Strategies\SafeKeysStrategy;
use Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy;

/*
|--------------------------------------------------------------------------
| Shared patterns
|--------------------------------------------------------------------------
|
| Listed once and spread into each profile below, so the profiles cannot
| drift apart: a credential the default profile catches is caught by the
| strict and observability profiles too.
|
| Order matters where two rules can match the same text. On an equal score
| the rule listed first wins the overlap, which is why url_with_auth sits
| ahead of email (the password in "https://user:pass@host" looks like an
| address) and anthropic ahead of openai (both begin "sk-").
|
| `keywords` is a prefilter: the pattern is only tried on a value containing
| one of the literals, compared case-insensitively. It keeps expensive rules
| off values that cannot match, and lets a rule like phone_bare demand a
| label before it believes a bare run of digits.
|
*/

$credentialPatterns = [
    'url_with_auth' => [
        // Any scheme - postgres://, redis://, amqp://, https:// - and only the
        // password is replaced, so the host and path stay readable.
        'pattern' => '/([a-z][a-z0-9+.-]*:\/\/[^:\/\s@]*:)([^@\/\s]+)(@)/i',
        'capture' => 2,
        'entity' => 'url_credentials',
        'confidence' => 0.9,
        'keywords' => ['://'],
    ],
    'private_key_block' => [
        'pattern' => '/-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----/',
        'entity' => 'private_key',
        'confidence' => 1.0,
        'keywords' => ['private key'],
    ],
    'jwt' => [
        'pattern' => '/\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/',
        'entity' => 'jwt',
        'confidence' => 0.9,
        'keywords' => ['eyj'],
    ],
    'bearer_token' => [
        'pattern' => '/(bearer\s+)([A-Za-z0-9._~+\/=-]{16,})/i',
        'capture' => 2,
        'entity' => 'bearer_token',
        'confidence' => 0.85,
        'keywords' => ['bearer'],
    ],
    'aws_access_key' => [
        'pattern' => '/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/',
        'entity' => 'aws_access_key',
        'confidence' => 0.9,
        'keywords' => ['akia', 'asia'],
    ],
    'github_token' => [
        'pattern' => '/\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/',
        'entity' => 'github_token',
        'confidence' => 0.95,
        'keywords' => ['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_'],
    ],
    'stripe_key' => [
        // Secret and restricted keys only; publishable keys are meant to be seen.
        'pattern' => '/\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,99}\b/',
        'entity' => 'stripe_key',
        'confidence' => 0.95,
        'keywords' => ['sk_', 'rk_'],
    ],
    'slack_token' => [
        'pattern' => '/\bxox[abpors]-[A-Za-z0-9-]{10,}\b/',
        'entity' => 'slack_token',
        'confidence' => 0.9,
        'keywords' => ['xox'],
    ],
    'anthropic_key' => [
        'pattern' => '/\bsk-ant-[A-Za-z0-9_-]{20,}\b/',
        'entity' => 'anthropic_key',
        'confidence' => 0.95,
        'keywords' => ['sk-ant-'],
    ],
    'openai_key' => [
        'pattern' => '/\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/',
        'entity' => 'openai_key',
        'confidence' => 0.9,
        'keywords' => ['sk-'],
    ],
    'google_api_key' => [
        'pattern' => '/\bAIza[0-9A-Za-z_-]{35}\b/',
        'entity' => 'google_api_key',
        'confidence' => 0.9,
        'keywords' => ['aiza'],
    ],
    'sendgrid_key' => [
        'pattern' => '/\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/',
        'entity' => 'sendgrid_key',
        'confidence' => 0.95,
        'keywords' => ['sg.'],
    ],
];

$identityPatterns = [
    'email' => [
        // Byte-level rather than /u so a non-ASCII local part or domain
        // matches without PCRE validating the whole value as UTF-8 first.
        'pattern' => '/[A-Za-z0-9_.+\-\x80-\xff]+@[A-Za-z0-9\-\x80-\xff]+(?:\.[A-Za-z0-9\-\x80-\xff]+)+/',
        'entity' => 'email',
        'confidence' => 0.8,
        'keywords' => ['@'],
    ],
    'phone_formatted' => [
        // Needs separators or parentheses, so a date, a version or a card
        // number is not mistaken for a phone number.
        'pattern' => '/(?<!\d)(?<!\d[\s.-])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)|\d{2,4})[\s.-]\d{3,4}[\s.-]\d{3,4}(?![\s.-]?\d)/',
        'entity' => 'phone',
        'confidence' => 0.6,
    ],
    'phone_e164' => [
        'pattern' => '/(?<!\d)\+\d{9,15}(?!\d)/',
        'entity' => 'phone',
        'confidence' => 0.7,
        'keywords' => ['+'],
    ],
    'phone_bare' => [
        // A bare ten-digit run is a Unix timestamp or an order number far
        // more often than a phone number, so it needs a label nearby.
        'pattern' => '/(?<!\d)\d{10}(?!\d)/',
        'entity' => 'phone',
        'confidence' => 0.5,
        'keywords' => ['phone', 'tel', 'mobile', 'cell', 'fax'],
    ],
    'ssn' => [
        'pattern' => '/\b\d{3}-\d{2}-\d{4}\b/',
        // Rejects the never-issued area/group/serial values, which is most
        // of what matches this shape by accident.
        'validator' => 'ssn',
        'entity' => 'ssn',
        'confidence' => 0.7,
    ],
    'ssn_bare' => [
        'pattern' => '/(?<!\d)\d{9}(?!\d)/',
        'validator' => 'ssn',
        'entity' => 'ssn',
        'confidence' => 0.4,
        'keywords' => ['ssn', 'social security', 'tax id', 'tin'],
    ],
    'credit_card' => [
        'pattern' => '/\b(?:\d[ -]*?){13,16}\b/',
        // Without the Luhn check this matches any 13-16 digit run: order
        // numbers, tracking codes, concatenated timestamps.
        'validator' => 'luhn',
        'entity' => 'credit_card',
    ],
    'iban' => [
        // Accepts the spaced form banks print as well as the compact one.
        'pattern' => '/\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b/',
        'validator' => 'iban',
        'entity' => 'iban',
    ],
];

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
        | Files are scanned a window of lines at a time, so memory stays flat
        | whatever the file size - the files most worth scanning are the large
        | ones. Windows overlap so a secret spanning a boundary (a PEM block, a
        | wrapped connection string) is still found; duplicates from the overlap
        | are dropped by fingerprint.
        */
        'window_lines' => env('REDACTOR_SCAN_WINDOW_LINES', 512),
        'overlap_lines' => env('REDACTOR_SCAN_OVERLAP_LINES', 4),

        /*
        |----------------------------------------------------------------------
        | Credential verification
        |----------------------------------------------------------------------
        |
        | Asks each provider whether a detected credential is still live, which
        | turns a wall of maybes into a short list of keys to rotate today.
        |
        | It also sends real secrets to third parties. Nothing here happens
        | unless all three of these agree:
        |
        |   1. enabled is true                (this file, reviewable in a diff)
        |   2. the run passes --verify        (a human, per run)
        |   3. the provider is listed below   (who you are willing to tell)
        |
        | An empty list means none. Enabling the feature and choosing who to
        | trust with the secrets are deliberately separate decisions, and
        | redaction itself can never trigger this - only the scan command can.
        |
        */
        'verification' => [
            'enabled' => env('REDACTOR_SCAN_VERIFY', false),

            'verifiers' => [
                // 'github_token',
                // 'stripe_key',
                // 'slack_token',
            ],
        ],

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
    | Pseudonymization
    |--------------------------------------------------------------------------
    |
    | The `hash` and `surrogate` operators replace a value with a stable
    | stand-in, so redacted logs stay joinable: the same email always produces
    | the same surrogate, and you can still count distinct users or follow one
    | account through a trace.
    |
    | The mapping is one-way (HMAC, not encryption). Anyone holding the key can
    | confirm a guess, so the key must not travel with the logs. Leave it null
    | to derive one from APP_KEY, which is never used directly.
    |
    | Rotating the key changes every surrogate. That is the intended way to
    | break correlation with previously exported logs - and the reason not to
    | rotate it casually.
    |
    */

    'pseudonymization' => [
        'enabled' => env('REDACTOR_PSEUDONYMIZATION', true),
        'key' => env('REDACTOR_PSEUDONYMIZATION_KEY'),

        /*
        | Mixed into every surrogate. Shared by every profile, so the same
        | user gets the same surrogate on every channel and the logs stay
        | joinable across them. A profile may set its own `pseudonymization`
        | `salt` to deliberately break that correlation - an export that must
        | not be linkable back to the application logs, say.
        */
        'salt' => env('REDACTOR_PSEUDONYMIZATION_SALT'),
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
            | The shared credential and identity rules, in that order. See
            | the top of this file for why the order matters and what
            | `keywords` does.
            */
            'patterns' => [
                ...$credentialPatterns,
                ...$identityPatterns,
            ],

            /*
            | Rules that name a location outright.
            |
            |   request.headers.authorization   exactly there
            |   user.*.email                    any single level between
            |   **.password                     at any depth
            |   users[*].token                  through a list
            |
            | Checked before anything else and, when one matches, instead of
            | everything else - no key guessing, no scanning of the contents,
            | no walk below the matched node. A path says where; every other
            | rule in this file is inferring it.
            |
            | The more specific pattern wins, so declaration order never
            | matters, and `preserve` carves an exception out of a broader rule
            | without disabling it.
            */
            'paths' => [
                // 'request.headers.authorization' => 'redact',
                // 'user.email'                    => 'surrogate',
                // 'debug'                         => 'preserve',
            ],

            /*
            | What happens to what the detectors find, by entity.
            |
            |   redact     replace with the replacement string  (default)
            |   mask       same length, all mask characters
            |   partial    keep the last N characters
            |   remove     delete it
            |   hash       stable keyed token: [email:k4m9rp2xzq]
            |   surrogate  stable fake of the same shape
            |   preserve   detect and report, change nothing
            |
            | Entity beats the rule that found it, so a policy decision about
            | data is not overridden by which regex happened to spot it.
            */
            'operators' => [
                'default' => 'redact',
                'credit_card' => ['partial' => ['keep' => 4]],
            ],

            /*
            | Detections scoring below this are ignored. Raise it to quieten a
            | noisy profile without weakening any pattern.
            */
            'min_confidence' => env('REDACTOR_MIN_CONFIDENCE', 0.0),

            'replacement' => env('REDACTOR_REPLACEMENT', '[REDACTED]'),
            'mark_redacted' => env('REDACTOR_MARK_REDACTED', true),
            'track_redacted_keys' => env('REDACTOR_TRACK_KEYS', false),
            'non_redactable_object_behavior' => env('REDACTOR_OBJECT_BEHAVIOR', 'preserve'),
            'max_value_length' => env('REDACTOR_MAX_VALUE_LENGTH', 5000),

            /*
            | What happens to a string over max_value_length.
            |
            |   truncate   keep the head, scan it, note what was cut  (default)
            |   redact     replace the whole value
            |
            | The values most often over the limit in a Laravel log are stack
            | traces and request bodies - the part the reader needed - so the
            | default keeps what it can rather than replacing all of it.
            */
            'large_string_behavior' => env('REDACTOR_LARGE_STRING_BEHAVIOR', 'truncate'),
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
                ...$credentialPatterns,
                ...$identityPatterns,
                'ipv4' => [
                    'pattern' => '/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/',
                    'entity' => 'ip',
                    'confidence' => 0.8,
                ],
                'uuid' => [
                    'pattern' => '/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i',
                    'entity' => 'uuid',
                    'confidence' => 0.8,
                ],
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
                ...$credentialPatterns,
                ...$identityPatterns,

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

            'operators' => [
                'default' => 'redact',
                'credit_card' => ['partial' => ['keep' => 4]],
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
        | Observability Profile
        |----------------------------------------------------------------------
        |
        | For logs and traces you still need to be able to reason about.
        |
        | Replacing every value with "[REDACTED]" collapses distinct values into
        | one, which destroys exactly the questions logs exist to answer: how
        | many users hit this, is it always the same account, did this session
        | span both services. This profile pseudonymises instead - the same
        | input always yields the same stand-in - so counts, joins and traces
        | survive while the original values do not.
        |
        | Requires a pseudonymization key (see above). Without one it degrades
        | to plain redaction rather than emitting an unkeyed surrogate.
        |
        */
        'observability' => [
            'enabled' => true,

            'strategies' => [
                SafeKeysStrategy::class,
                BlockedKeysStrategy::class,
                RegexPatternsStrategy::class,
                ShannonEntropyStrategy::class,
            ],

            'safe_keys' => [
                'id', 'uuid', 'user_id', 'order_id', 'request_id', 'trace_id',
                'created_at', 'updated_at', 'timestamp', 'level', 'event',
                'channel', 'duration_ms', 'memory_mb', 'status', 'method',
                'type', 'action', 'operation', 'version', 'environment',
            ],

            'blocked_keys' => [
                'password', '*token*', '*secret*', 'authorization', 'private_key',
                'client_secret', 'cvv', 'pin',
            ],

            'patterns' => [
                ...$credentialPatterns,
                ...$identityPatterns,
                'ipv4' => [
                    'pattern' => '/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/',
                    'entity' => 'ip',
                    'confidence' => 0.8,
                ],
            ],

            /*
            | Emails keep their domain, so "how many distinct users at this
            | tenant" still answers correctly. Cards keep their BIN and stay
            | Luhn-valid. IPs become a different-but-stable address, so rate
            | analysis by source survives.
            */
            'paths' => [
                'request.headers.authorization' => 'redact',
                'request.headers.cookie' => 'redact',
                '**.password' => 'redact',
            ],

            'operators' => [
                'default' => 'redact',
                'email' => ['surrogate' => ['preserve_domain' => true]],
                'phone' => 'surrogate',
                'ip' => 'surrogate',
                'credit_card' => ['surrogate' => ['preserve_bin' => 6]],
            ],

            'min_confidence' => 0.4,

            'replacement' => '[REDACTED]',
            'mark_redacted' => false,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => 5000,
            'redact_large_objects' => true,
            'max_object_size' => 100,
            'max_depth' => 32,

            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.8,
                'min_length' => 25,
                'charset_thresholds' => [
                    'hex' => 3.0,
                    'base64' => 4.5,
                    'base64url' => 4.5,
                ],
                'exclusion_patterns' => [
                    '/^https?:\\/\\//',
                    '/^\\d{4}-\\d{2}-\\d{2}/',
                    '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i',
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

            // Minimal, fast patterns only. Every rule here is gated on a
            // literal, so a value without one costs a str_contains() and
            // nothing more.
            'patterns' => [
                'email' => $identityPatterns['email'],
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
