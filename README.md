# Kirschbaum Redactor

![Laravel Supported Versions](https://img.shields.io/badge/laravel-10.x/11.x/12.x-green.svg)
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

## Core Concepts

### Redaction Strategies

The package uses a class-based configuration:

1. **SafeKeysStrategy** - Preserves safe keys like `id`, `user_id`
2. **BlockedKeysStrategy** - Always redacts blocked keys like `password`, `secret`
3. **LargeObjectStrategy** - Redacts objects/arrays exceeding size limits
4. **LargeStringStrategy** - Redacts strings exceeding length limits
5. **RegexPatternsStrategy** - Custom regex patterns for emails, credit cards, etc.
6. **ShannonEntropyStrategy** - Detects high-entropy strings (API keys, tokens)

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
                'email' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/',
                'credit_card' => '/\b(?:\d[ -]*?){13,16}\b/',
                'ssn' => '/\b\d{3}-?\d{2}-?\d{4}\b/',
                'phone_simple' => '/\b\d{3}[.-]?\d{3}[.-]?\d{4}\b/',
                'url_with_auth' => '/https?:\/\/[^:\/\s]+:[^@\/\s]+@[^\s]+/',
            ],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve', // 'preserve', 'remove', 'redact', 'empty_array'
            'max_value_length' => 5000,
            'redact_large_objects' => true,
            'max_object_size' => 100,
            
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.8,  // Higher = more selective
                'min_length' => 25,  // Only analyze strings this long or longer
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

- Exact matches are faster than wildcard patterns
- Simple wildcards (`*word*`) are faster than complex multi-wildcard patterns
- Consider placing more specific patterns before broader ones
- Use exact matches when you know the specific key names

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

For automatic redaction of all log entries, use the `CustomLogTap` with Laravel's logging configuration. In your `config/logging.php`, add the tap to any channel:

```php
'channels' => [
    'stack' => [
        'driver' => 'stack',
        'channels' => explode(',', env('LOG_STACK', 'single')),
        'ignore_exceptions' => false,
        'tap' => [Kirschbaum\Redactor\Logging\CustomLogTap::class],
    ],
    
    'single' => [
        'driver' => 'single',
        'path' => storage_path('logs/laravel.log'),
        'level' => env('LOG_LEVEL', 'debug'),
        'tap' => [Kirschbaum\Redactor\Logging\CustomLogTap::class],
    ],
    
    'daily' => [
        'driver' => 'daily',
        'path' => storage_path('logs/laravel.log'),
        'level' => env('LOG_LEVEL', 'debug'),
        'days' => 14,
        'tap' => [Kirschbaum\Redactor\Logging\CustomLogTap::class],
    ],
],
```

With this configuration, all log entries will automatically have their context data redacted before being written to logs. The tap uses the `default` redaction profile unless otherwise configured.

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
        $context->markRedacted();
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

// Direct Instantiation (gets fresh instance - no state conflicts)
$redactor = new \Kirschbaum\Redactor\Redactor();
$result = $redactor->redact($data, 'profile_name');

// Check available profiles
$profiles = Redactor::getAvailableProfiles();
$exists = Redactor::profileExists('custom_profile');
```

## Built-in Profiles

- **`default`**: Balanced redaction for general logging and debugging
- **`strict`**: Aggressive redaction for sensitive contexts and audit trails  
- **`performance`**: Minimal redaction optimized for high-throughput scenarios

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
REDACTOR_SHANNON_ENABLED=true
REDACTOR_SHANNON_THRESHOLD=4.8
REDACTOR_SHANNON_MIN_LENGTH=25
```

## File Scanning Command

The package includes a console command to scan files and directories for sensitive content:

```bash
# Scan specific files
php artisan redactor:scan path/to/sensitive-file.txt

# Scan directories (scans entire project by default)
php artisan redactor:scan app/ config/

# Scan with custom profile
php artisan redactor:scan --profile=strict app/

# Exit with error code if sensitive content found (useful for CI)
php artisan redactor:scan --bail app/

# JSON output for programmatic use
php artisan redactor:scan --output=json config/

# Summary only (no per-file details)
php artisan redactor:scan --summary-only
```

The scanner uses the `file_scan` profile by default, which is optimized for plain text content and detects:
- API keys, tokens, and secrets
- Email addresses and personal information
- High-entropy strings (potential keys/tokens)
- Credit cards, SSNs, phone numbers
- Passwords and authentication strings

Results show **CLEAN**, **FINDINGS**, or **SKIPPED** status for each file, with a summary of total files scanned and findings detected.

## Requirements

- PHP 8.3+
- Laravel 11.x or 12.x

## Installation

```bash
composer require kirschbaum-development/redactor
php artisan vendor:publish --tag=redactor-config
```

## Testing

```bash
# Run tests
./vendor/bin/pest

# Run tests with coverage
./vendor/bin/pest --coverage
```

## Roadmap
- Add Laravel custom log formatter to tap logs and automatically redact sensitive data
- Add supoprt for partial replacement of sensitive data (low priority)

## License

MIT License. See [LICENSE.md](LICENSE.md) for details.

