# Kirschbaum Redactor

![Laravel Supported Versions](https://img.shields.io/badge/laravel-12.x%20%7C%2013.x-green.svg)
[![MIT Licensed](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Latest Version on Packagist](https://img.shields.io/packagist/v/kirschbaum-development/redactor.svg?style=flat-square)](https://packagist.org/packages/kirschbaum-development/redactor)
![Application Testing](https://github.com/kirschbaum-development/redactor/actions/workflows/php-tests.yml/badge.svg)
![Static Analysis](https://github.com/kirschbaum-development/redactor/actions/workflows/static-analysis.yml/badge.svg)
![Code Style](https://github.com/kirschbaum-development/redactor/actions/workflows/style-check.yml/badge.svg)

Redactor removes sensitive data from anything a Laravel application emits before it leaves: log records, HTTP responses, streamed output, MCP tool results, prompts sent to a language model, exports and queued jobs. It finds sensitive values by the key they sit under, by what they look like (credential patterns with checksum validators, Shannon entropy, an optional named entity recogniser) and by where they live in a payload, then replaces only the sensitive span so the text around it survives.

What replaces a value is a separate, per-entity decision. The same email address can become `[REDACTED]` in an audit log, a stable pseudonym like `u_7f3ac9@customer.com` in an application log so counts and joins still work, or a reversible token like `tok_email_k4m9rp2xzq` in front of a model so the application can act on the answer. Profiles bundle the rules and the decisions, and every boundary takes a profile name. The same engine scans files and git history from `redactor:scan`, with SARIF output, baselines and optional live-credential verification.

## Quick Start

Install the package and publish its configuration:

```bash
composer require kirschbaum-development/redactor
php artisan vendor:publish --tag=redactor-config
```

Add the tap to a log channel in `config/logging.php`. It pushes a Monolog processor, so the channel keeps its own formatter:

```php
'stack' => [
    'driver' => 'stack',
    'channels' => explode(',', env('LOG_STACK', 'single')),
    'tap' => [Kirschbaum\Redactor\Logging\RedactorTap::class],
],
```

Redact anything else directly:

```php
use Kirschbaum\Redactor\Facades\Redactor;

Redactor::redact([
    'user_id' => 123,
    'password' => 'hunter2',
    'email' => 'bob@example.com',
    'note' => 'card 4111 1111 1111 1111 on file',
]);

// [
//     'user_id' => 123,
//     'password' => '[REDACTED]',
//     'email' => '[REDACTED]',
//     'note' => 'card ***************1111 on file',
//     '_redacted' => true,
// ]
```

Ask what was found rather than reading it back out of the payload:

```php
$result = Redactor::profile('strict')->withoutMarkers()->inspect($data);

$result->value;         // the redacted payload
$result->wasRedacted;   // true
$result->redactedKeys;  // ['password', 'email']
$result->findings;      // rule, entity, key, offset, length and confidence for each match
```

## How It Works

A **profile** is one complete configuration: the strategies to run, the keys that are safe or blocked, the patterns to look for, and what to do with what is found. Five ship: `default`, `strict`, `observability`, `file_scan` and `performance`. Every entry point takes a profile name, so the same value can be pseudonymised on one channel and removed on another.

**Strategies** run in the order the profile lists them. Key rules decide by the name a value sits under; pattern rules, known secrets, entropy and entity recognition decide by content and report what they found and where; path rules decide by location and are checked before anything else. Detections are resolved once, so two rules matching the same text produce one rewrite and a surrogate written for one detection is never re-detected by the next.

**Operators** decide what replaces a detection, per entity rather than per rule:

```php
'operators' => [
    'default'     => 'redact',                                    // [REDACTED]
    'email'       => ['surrogate' => ['preserve_domain' => true]], // u_7f3ac9@customer.com, stable
    'credit_card' => ['partial' => ['keep' => 4]],                 // ************1111
    'ssn'         => 'nullify',                                    // null, so a typed field stays typed
],
```

`surrogate`, `hash` and `tokenize` are keyed with an HMAC derived from `APP_KEY` (or a key of your own), so the same input always yields the same stand-in and logs stay joinable without a route back to the original.

**Scanning** runs the same rules over files and git history:

```bash
php artisan redactor:scan --staged --bail             # the pre-commit gate
php artisan redactor:scan --diff=origin/main --output=sarif > redactor.sarif
php artisan redactor:scan --update-baseline           # accept what is already there
```

## What It Covers

- **Log channels** through `RedactorTap`, which never throws: a broken profile replaces the record rather than taking the channel down.
- **HTTP responses** through the `redact` middleware: JSON as data, text as text, streams as they stream, files untouched, failing closed to a 500.
- **Streams** through `StreamRedactor`, which holds back a window so a secret split across two chunks is still caught.
- **MCP servers** through the `RedactsResponses` trait on a Laravel MCP server: tool results, structured content, resources, prompts, streamed output and errors.
- **AI agents** through the `RedactPrompt` middleware for Laravel's AI package: the prompt is redacted on the way out and tokens are resolved in the answer.
- **Exports, jobs, error reporters and third-party clients** through `Redactor::redact()` and `redactSafely()` with a profile per destination.
- **Files and git history** through `redactor:scan`, with table, JSON, SARIF and JUnit output, `--staged`, `--diff` and `--history` modes, baselines, inline `redactor:allow` markers, and a publishable pre-commit hook and GitHub workflow.
- **Your test suite** through `Redactor::fake()`, so a test can assert that a secret never left.

## Documentation

The full documentation lives in [`docs/`](docs/README.md):

| Page | What it covers |
| --- | --- |
| [Getting Started](docs/getting-started.md) | Installation, the Monolog tap, `redact()`, `inspect()`, the fluent builder, profiles and the five that ship. |
| [Configuration](docs/configuration.md) | Every key in `config/redactor.php` with its type, default and environment variable; the shipped profiles compared. |
| [Rules](docs/rules.md) | Pattern rules, validators, keywords, samples, dictionary rules, allow-lists, path rules, safe and blocked keys, known secrets, confidence and how detections are resolved. |
| [Operators and Pseudonymisation](docs/operators-and-pseudonymisation.md) | Every operator with example output, precedence, surrogates, the key and salt, reversible tokens and `detokenize()`. |
| [Boundaries](docs/boundaries.md) | Log channels, HTTP responses, streams, MCP servers, AI agents, exports and jobs, and the `RedactionPerformed` event. |
| [Scanning](docs/scanning.md) | `redactor:scan` in full: paths, output formats, git modes, decoding, baselines, suppression, verification, the hook and workflow, exit codes. |
| [Entity Recognition](docs/entity-recognition.md) | Finding names, places and organisations in prose with a Presidio-compatible recogniser, and when not to. |
| [Testing](docs/testing.md) | `Redactor::fake()` and its assertions, `redactor:validate`, rule samples, the package's own test conventions. |
| [Extending](docs/extending.md) | Every contract, how to register each, a worked custom strategy and operator, and macros. |
| [Upgrading](docs/upgrading.md) | Every renamed class and method from 0.1.0, every behaviour change, and what to do about each. |

## Requirements

- PHP 8.3, 8.4 or 8.5
- Laravel 12.x or 13.x

`laravel/mcp` and `laravel/ai` are suggested, not required; the adapters for them are only loaded when you use them.

## Testing

```bash
composer test           # full suite, in parallel
composer test-coverage  # with the coverage floor enforced
composer lint           # Pint, Rector, PHPStan (level 10, no baseline)
composer rector:check   # what Rector would change, without changing it
composer mutate         # mutation testing (Pest); local only, not run in CI
composer preflight      # everything CI runs
```

Coverage and mutation testing need a coverage driver (pcov or Xdebug) loaded in the CLI. See [Testing](docs/testing.md) for the conventions and for `Redactor::fake()` in your own suite.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for what changed in each release and [Upgrading](docs/upgrading.md) for how to move from 0.1.0.

## License

MIT License. See [LICENSE.md](LICENSE.md) for details.
