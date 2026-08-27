# Kirschbaum Redactor

![Laravel Supported Versions](https://img.shields.io/badge/laravel-11.x%20%7C%2012.x-green.svg)
[![MIT Licensed](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Latest Version on Packagist](https://img.shields.io/packagist/v/kirschbaum-development/redactor.svg?style=flat-square)](https://packagist.org/packages/kirschbaum-development/redactor)
![Application Testing](https://github.com/kirschbaum-development/redactor/actions/workflows/php-tests.yml/badge.svg)
![Static Analysis](https://github.com/kirschbaum-development/redactor/actions/workflows/static-analysis.yml/badge.svg)
![Code Style](https://github.com/kirschbaum-development/redactor/actions/workflows/style-check.yml/badge.svg)

Automatically redact sensitive data from arrays, objects, and strings before logging or exporting. Features a class-based strategy system with profile-based configurations, Shannon entropy detection.

> This package is in active development and its API can change abruptly without any notice. Please reach out if you plan to use it in a production environment.


## Quick Start

```bash
composer require kirschbaum-development/redactor
php artisan vendor:publish --tag=redactor-config
```

The package automatically registers the service provider and facade. Use it directly:

```php
use Kirschbaum\Redactor\Facades\Redactor;

// Basic usage
$data = [
    'user_id' => 123,
    'password' => 'secret123',
    'api_key' => 'sk-1234567890abcdef1234567890abcdef12345678',
    'email' => 'user@example.com'
];

$redacted = Redactor::redact($data);
// Result:
// [
//     'user_id' => 123,                    // Safe key - preserved
//     'password' => '[REDACTED]',          // Blocked key - redacted
//     'api_key' => '[REDACTED]',           // High entropy - redacted
//     'email' => '[REDACTED]',             // Email pattern - redacted
//     '_redacted' => true                  // Metadata added
// ]
```

Redaction replaces the sensitive span, not the whole value, so the surrounding
text survives:

```php
Redactor::redact('User bob@example.com placed order 123');
// 'User [REDACTED] placed order 123'
```

If you need to know whether anything matched, ask for the metadata rather than
reading it back out of the payload:

```php
$result = Redactor::redactWithMetadata($data);

$result->value;         // the redacted payload
$result->wasRedacted;   // bool
$result->redactedKeys;  // ['password', 'api_key', 'email']
$result->findings;      // rule name, offset and length for each match
```

## Core Concepts

### Redaction Strategies

The package uses a class-based configuration:

1. **SafeKeysStrategy** - Preserves safe keys like `id`, `user_id`
2. **BlockedKeysStrategy** - Always redacts blocked keys like `password`, `secret`
3. **LargeObjectStrategy** - Redacts objects/arrays exceeding size limits
4. **LargeStringStrategy** - Redacts strings exceeding length limits
5. **RegexPatternsStrategy** - Custom regex patterns for emails, credit cards, etc.
6. **ShannonEntropyStrategy** - Detects high-entropy strings (API keys, tokens)

Strategies run in the order the profile lists them, and the chain stops at the
first strategy that replaces a value outright. Strategies that only rewrite part
of a string - the regex and entropy ones - hand the result to the rest of the
chain, so an API key sitting next to an email address is not spared because the
email matched first.

Two of them are special:

- `SafeKeysStrategy` **preserves** rather than redacts. It ends the chain *and*
  stops the walk, so everything nested under a safe key is emitted untouched.
  Only list keys whose contents cannot carry sensitive data by construction -
  identifiers, timestamps, enumerations. A free-text field like `message` is not
  safe just because it usually looks harmless.
- Every regex is evaluated fail-closed. If PCRE gives up on a pattern - backtrack
  limit, JIT stack limit, bad UTF-8 - the value is treated as sensitive rather
  than clean, and the failure is logged with the rule name.

### Profiles

Profiles provide different redaction configurations for different contexts:

```php
// Use built-in profiles
$logData = Redactor::redact($data, 'default');       // Balanced redaction
$auditData = Redactor::redact($data, 'strict');      // Aggressive redaction  
$debugData = Redactor::redact($data, 'performance'); // Minimal redaction for speed
```

## Configuration

The config file (`config/redactor.php`) uses a class-based approach:

```php
return [
    'default_profile' => 'default',
    
    'profiles' => [
        'default' => [
            'enabled' => true,
            
            // Strategies executed in array order (top-to-bottom priority)
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\LargeObjectStrategy::class,
                \Kirschbaum\Redactor\Strategies\LargeStringStrategy::class,
                \Kirschbaum\Redactor\Strategies\RegexPatternsStrategy::class,
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            
            'safe_keys' => ['id', 'user_id', 'uuid', 'created_at', 'updated_at'],
            'blocked_keys' => ['password', 'secret', 'token', 'api_key', 'authorization'],
            'patterns' => [
                // Shorthand: matched span replaced with the replacement string
                'email' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/',
                'phone_simple' => '/\b\d{3}[.-]?\d{3}[.-]?\d{4}\b/',

                // Full rule form - see "Pattern Rules" below
                'credit_card' => [
                    'pattern' => '/\b(?:\d[ -]*?){13,16}\b/',
                    'validator' => 'luhn',    // reject non-cards of the same shape
                    'mode' => 'partial',      // ************1111
                    'keep' => 4,
                ],
                'ssn' => [
                    'pattern' => '/\b\d{3}-?\d{2}-?\d{4}\b/',
                    'validator' => 'ssn',
                ],
                'url_with_auth' => [
                    'pattern' => '/(https?:\/\/[^:\/\s]+:)([^@\/\s]+)(@)/',
                    'capture' => 2,           // replace the credentials, keep the host
                ],
            ],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve', // 'preserve', 'remove', 'redact', 'empty_array'
            'max_value_length' => 5000,
            'redact_large_objects' => true,
            'max_object_size' => 100,
            'max_depth' => 32,   // guards cyclic and pathologically nested payloads

            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.8,  // Higher = more selective
                'min_length' => 25,  // Only analyze strings this long or longer

                // Per-alphabet thresholds. A hex digest cannot exceed 4.0 bits
                // per character, so judging it at 4.8 guarantees a miss.
                'charset_thresholds' => [
                    'hex' => 3.0,
                    'base64' => 4.5,
                    'base64url' => 4.5,
                ],

                'exclusion_patterns' => [
                    '/^https?:\/\//', // URLs
                    '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', // UUIDs
                    '/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/',      // IP addresses
                    '/^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i', // MAC addresses
                ],
            ],
        ],
    ],
];
```

## Pattern Rules

A pattern can be a bare regex, or a rule that says what to do with what it
matches:

```php
'patterns' => [
    'email' => '/[^@\s]+@[^@\s]+/',   // shorthand

    'credit_card' => [
        'pattern'        => '/\b(?:\d[ -]*?){13,16}\b/',
        'mode'           => 'partial',
        'keep'           => 4,
        'mask_character' => '*',
        'validator'      => 'luhn',
    ],
],
```

### Modes

| Mode | Result for `4111111111111111` |
| --- | --- |
| `replace` *(default)* | `[REDACTED]` |
| `mask` | `****************` (length preserved) |
| `partial` | `************1111` (last `keep` characters kept) |
| `remove` | *(deleted)* |
| `full` | the **entire value** is replaced, not just the match |

Character counts are multibyte-aware. An unrecognised mode is a configuration
error, not a silent fallback.

### Capture groups

Some patterns need surrounding context to match confidently, but that context is
not itself sensitive. Name the group holding the secret and the rest survives:

```php
'aws_secret_key' => [
    'pattern' => '/(aws_secret_access_key\s*=\s*)([A-Za-z0-9\/+]{40})/i',
    'capture' => 2,
],

// aws_secret_access_key = [REDACTED]
```

### Validators

A regex asserts shape only: `/\b(?:\d[ -]*?){13,16}\b/` matches order numbers
and concatenated timestamps as readily as cards. A validator asserts the value
could actually be what the pattern claims. A match that fails is left untouched.

| Validator | Check |
| --- | --- |
| `luhn` | Payment card check digit, 12-19 digits |
| `iban` | ISO 13616 mod-97 |
| `ssn` | US allocation rules (area 000/666/900+, group 00, serial 0000) |

```php
Redactor::redact('order 2024010112000001 shipped');  // untouched - fails Luhn
Redactor::redact('paid with 4111111111111111');      // 'paid with ************1111'
```

## Wildcard Patterns

The `BlockedKeysStrategy` and `SafeKeysStrategy` support powerful wildcard patterns using the `*` character. This allows you to match multiple key variations without listing each one explicitly.

### Basic Wildcard Usage

```php
// config/redactor.php
'profiles' => [
    'wildcard_example' => [
        'enabled' => true,
        'strategies' => [
            \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
        ],
        'blocked_keys' => [
            '*token*',        // Matches any key containing "token"
            '*key*',          // Matches any key containing "key"  
            'password',       // Exact match (no wildcards)
            'user_*_data',    // Matches keys like "user_profile_data", "user_settings_data"
        ],
        // ... other config
    ],
];

// Usage example
$data = [
    'user_id' => 123,
    'api_token' => 'secret123',           // Matched by *token*
    'access_token' => 'abc123',           // Matched by *token*
    'my_custom_token' => 'xyz789',        // Matched by *token*
    'user_api_key' => 'key123',           // Matched by *key*
    'private_key_data' => 'private',      // Matched by *key*
    'password' => 'secret',               // Matched by exact "password"
    'user_profile_data' => 'profile',     // Matched by user_*_data
    'user_settings_data' => 'settings',   // Matched by user_*_data
    'normal_field' => 'safe_value',       // Not matched - preserved
];

$redacted = Redactor::redact($data, 'wildcard_example');
```

### Wildcard Pattern Types

#### Contains Pattern (`*word*`)
Matches any key that contains the specified word anywhere:

```php
'blocked_keys' => ['*token*', '*secret*', '*auth*'],

// Matches:
// - api_token, access_token, token_data, my_token_field
// - user_secret, secret_key, app_secret_config  
// - auth_header, oauth_token, authentication_data
```

#### Prefix Pattern (`word*`)
Matches any key that starts with the specified word:

```php
'blocked_keys' => ['password*', 'secret*', 'api*'],

// Matches:
// - password, password_hash, password_confirmation
// - secret, secret_key, secret_data
// - api, api_key, api_token, api_endpoint
```

#### Suffix Pattern (`*word`)
Matches any key that ends with the specified word:

```php
'blocked_keys' => ['*token', '*key', '*secret'],

// Matches:
// - access_token, api_token, user_token
// - private_key, public_key, encryption_key  
// - user_secret, app_secret, database_secret
```

#### Multi-Wildcard Patterns (`word*middle*word`)
Use multiple wildcards for complex patterns:

```php
'blocked_keys' => [
    'user_*_token',     // user_api_token, user_auth_token
    'app_*_*_key',      // app_private_encryption_key, app_public_signing_key
    '*_key_*',          // my_key_data, the_key_value, user_key_config
],
```

### Case-Insensitive Matching

All wildcard patterns are case-insensitive by default:

```php
'blocked_keys' => ['*TOKEN*'],

// Matches all of these:
// - API_TOKEN, api_token, Api_Token, MyTokenData, user_token_field
```

### Combining Exact and Wildcard Patterns

You can mix exact matches with wildcard patterns in the same configuration:

```php
'blocked_keys' => [
    'password',           // Exact match
    'secret',            // Exact match
    '*token*',           // Wildcard pattern
    '*_key_*',           // Complex wildcard
    'user_*_data',       // Specific structure
],

'safe_keys' => [
    'id',                // Exact match - always preserved
    'user_id',           // Exact match - always preserved  
    '*_count',           // Wildcard pattern - preserve counting fields
    'meta_*',            // Wildcard pattern - preserve metadata fields
],
```

### Performance Considerations

Pattern lists are compiled once and cached, with each pattern sorted into the
cheapest test for its shape - a hash lookup for exact names, `str_contains` for
`*word*`, `str_starts_with`/`str_ends_with` for one-sided wildcards. Only
multi-wildcard patterns like `user_*_token` reach PCRE.

In practice that means the shape of your list barely matters. If you are tuning
a very large one, prefer exact names and single-wildcard patterns over
multi-wildcard ones.

## Common Use Cases

### Logging Context

```php
use Kirschbaum\Redactor\Facades\Redactor;

// Before logging user actions
Log::info('User action', Redactor::redact([
    'user_id' => 123,
    'action' => 'login',
    'ip_address' => '192.168.1.1',
    'session_token' => 'abc123def456...',
    'user_agent' => 'Mozilla/5.0...',
    'api_response' => $sensitiveApiData,
]));
```

### Laravel Logging Integration

Add the tap to any channel in `config/logging.php`:

```php
'channels' => [
    'stack' => [
        'driver' => 'stack',
        'channels' => explode(',', env('LOG_STACK', 'single')),
        'ignore_exceptions' => false,
        'tap' => [Kirschbaum\Redactor\Logging\RedactorTap::class],
    ],

    'single' => [
        'driver' => 'single',
        'path' => storage_path('logs/laravel.log'),
        'level' => env('LOG_LEVEL', 'debug'),
        'tap' => [Kirschbaum\Redactor\Logging\RedactorTap::class],
    ],

    // Pass a profile name after a colon to override the default
    'audit' => [
        'driver' => 'daily',
        'path' => storage_path('logs/audit.log'),
        'tap' => [Kirschbaum\Redactor\Logging\RedactorTap::class.':strict'],
    ],
],
```

`RedactorTap` registers a Monolog **processor**, which redacts the record's
message, context and extra and then leaves the channel's own formatter alone -
so a channel writing JSON keeps writing JSON.

Redaction in the log path never throws. A profile name typo, an unreadable
config value or a strategy that blows up on unexpected input all fail *closed*:
the content is replaced rather than emitted, and logging keeps working. Validate
your profiles at deploy time so you find out earlier:

```bash
php artisan redactor:validate
```

#### Formatter alternative

`ReadactFormatter` is still available for channels that want a self-contained
drop-in. It owns the output format, so prefer the tap unless you specifically
want that. It can wrap an inner formatter rather than replace it:

```php
use Kirschbaum\Redactor\Logging\ReadactFormatter;
use Monolog\Formatter\JsonFormatter;

$handler->setFormatter(new ReadactFormatter(new JsonFormatter));
```

### API Response Sanitization

```php
use Kirschbaum\Redactor\Facades\Redactor;

// Before returning debug information
return response()->json([
    'debug' => Redactor::redact($requestData, 'performance'),
    'status' => 'processed'
]);
```

### Database Export & Auditing

```php
use Kirschbaum\Redactor\Facades\Redactor;

// Before exporting user data
$users = User::all()->map(function ($user) {
    return Redactor::redact($user->toArray(), 'strict');
});

// Audit trail with sensitive data redacted
$auditLog = Redactor::redact([
    'user_id' => $user->id,
    'changes' => $changes,
    'request_data' => request()->all(),
], 'audit');
```

### PCI Compliance Example

```php
// config/redactor.php
'profiles' => [
    'pci_compliant' => [
        'enabled' => true,
        'strategies' => [
            \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
            \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
            \Kirschbaum\Redactor\Strategies\RegexPatternsStrategy::class,
        ],
        'safe_keys' => ['order_id', 'customer_id', 'amount', 'currency'],
        'blocked_keys' => [
            'credit_card', 'cc_number', 'card_number', 'pan',
            'cvv', 'cvc', 'cvn', 'expiry', 'exp_date', 'security_code'
        ],
        'patterns' => [
            'credit_card' => '/\b(?:\d[ -]*?){13,16}\b/',
            'ssn' => '/\b\d{3}-?\d{2}-?\d{4}\b/',
            'routing_number' => '/\b\d{9}\b/',
        ],
        'replacement' => '[PCI_REDACTED]',
        'non_redactable_object_behavior' => 'redact',
    ],
];

// Usage
$orderData = Redactor::redact($order->toArray(), 'pci_compliant');
```

## Advanced Features

### Object Handling

The package handles various object types:

```php
use Kirschbaum\Redactor\Facades\Redactor;

// Laravel models (uses toArray())
$user = User::find(1);
$redacted = Redactor::redact($user);

// Plain objects (uses JSON serialization)
$object = new stdClass();
$object->secret = 'sensitive';
$redacted = Redactor::redact($object);

// Non-serializable objects (configurable behavior)
$resource = fopen('file.txt', 'r');
$redacted = Redactor::redact(['file' => $resource]);
// Behavior controlled by 'non_redactable_object_behavior' setting
```

### Custom Strategies

Create your own redaction logic with full type safety:

```php
use Kirschbaum\Redactor\Strategies\RedactionStrategyInterface;
use Kirschbaum\Redactor\RedactionContext;

class InternalDataStrategy implements RedactionStrategyInterface
{
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        return str_contains($key, 'internal_') || str_contains($key, 'debug_');
    }

    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        // recordRedaction() also reports the key and rule to the caller and to
        // the scanner; markRedacted() only sets the flag.
        $context->recordRedaction($key, 'internal_data');

        return '[INTERNAL]';
    }
}

// Register and use
use Kirschbaum\Redactor\Facades\Redactor;

Redactor::registerCustomStrategy('internal_data', new InternalDataStrategy());

// Add to profile configuration
'strategies' => [
    'internal_data', // Custom strategy by registered name
    \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
    // ... other strategies
],
```

### Multiple Usage Patterns

```php
// Via Facade (recommended)
use Kirschbaum\Redactor\Facades\Redactor;
$result = Redactor::redact($data, 'profile_name');

// Via Service Container
$redactor = app(\Kirschbaum\Redactor\Redactor::class);
$result = $redactor->redact($data, 'profile_name');

// Direct instantiation (a fresh instance with its own strategy cache;
// the container binding is a singleton)
$redactor = new \Kirschbaum\Redactor\Redactor();
$result = $redactor->redact($data, 'profile_name');

// Check available profiles
$profiles = Redactor::getAvailableProfiles();
$exists = Redactor::profileExists('custom_profile');
```

## Built-in Profiles

- **`default`**: Balanced redaction for general logging and debugging
- **`strict`**: Aggressive redaction for sensitive contexts and audit trails
- **`file_scan`**: Content patterns for `redactor:scan`; no key-based strategies
- **`performance`**: Minimal redaction optimised for high-throughput scenarios

## Environment Configuration

Many settings can be controlled via environment variables:

```env
REDACTOR_ENABLED=true
REDACTOR_DEFAULT_PROFILE=default
REDACTOR_REPLACEMENT="[REDACTED]"
REDACTOR_MARK_REDACTED=true
REDACTOR_TRACK_KEYS=false
REDACTOR_OBJECT_BEHAVIOR=preserve
REDACTOR_MAX_VALUE_LENGTH=5000
REDACTOR_LARGE_OBJECTS=true
REDACTOR_MAX_OBJECT_SIZE=100
REDACTOR_MAX_DEPTH=32
REDACTOR_SHANNON_ENABLED=true
REDACTOR_SHANNON_THRESHOLD=4.8
REDACTOR_SHANNON_MIN_LENGTH=25

# File scanning
REDACTOR_SCAN_PROFILE=file_scan
REDACTOR_SCAN_MAX_FILE_SIZE=10485760
REDACTOR_SCAN_SKIP_BINARY=true
REDACTOR_SCAN_RESPECT_GITIGNORE=true
REDACTOR_SCAN_BASELINE=.redactor-baseline.json
```

## File Scanning Command

Scan files and directories for sensitive content:

```bash
# Scan specific files, or the whole project by default
php artisan redactor:scan path/to/file.txt
php artisan redactor:scan app/ config/

# Fail the build when anything is found
php artisan redactor:scan --bail

# Machine-readable output
php artisan redactor:scan --output=json
php artisan redactor:scan --output=sarif > redactor.sarif

# A different profile
php artisan redactor:scan --profile=strict app/
```

Every finding names the rule that fired and where it fired, with an excerpt
taken from the *redacted* text - so reports can be shared without publishing the
secrets they report:

```
  Rule             Location            Excerpt
  aws_access_key   app/config.env:3:19 AWS_ACCESS_KEY_ID=[REDACTED]
  email            app/seed.php:12:24  'contact' => '[REDACTED]',
```

Files that are binary, larger than `max_file_size`, matched by an exclude
pattern, or already ignored by git are skipped.

### CI

`--output=sarif` produces SARIF 2.1.0, which GitHub renders inline on the pull
request:

```yaml
- run: php artisan redactor:scan --output=sarif > redactor.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: redactor.sarif
```

### Baselines

A repository with test fixtures or a documented example key can never go green
without a baseline, so record what you have accepted and let CI fail only on new
findings:

```bash
php artisan redactor:scan --update-baseline   # writes .redactor-baseline.json
php artisan redactor:scan --bail              # now fails only on new secrets
```

The baseline stores a hash of the rule, the path and the secret. The secret
itself is never written to the file, and a finding stays accepted when the code
around it moves.

## Requirements

- PHP 8.3, 8.4 or 8.5
- Laravel 11.x or 12.x

## Installation

```bash
composer require kirschbaum-development/redactor
php artisan vendor:publish --tag=redactor-config
```

## Testing

```bash
composer test           # full suite, in parallel
composer test-coverage  # with the coverage floor enforced
composer lint           # Pint + PHPStan (level 10, no baseline)
composer mutate         # mutation testing (Pest)
composer preflight      # everything CI runs
```

## Roadmap

Done since the last release: partial (span-level) replacement, a Monolog
processor integration, structured scan findings with SARIF output and baselines,
checksum validators, and per-alphabet entropy thresholds.

Still open:

- Compiled path rules (`context.user.*.email`) as an alternative to key matching
- Deterministic pseudonymisation, so redacted logs stay joinable
- Streaming file scanning for very large files
- Optional live verification of detected credentials

## License

MIT License. See [LICENSE.md](LICENSE.md) for details.

