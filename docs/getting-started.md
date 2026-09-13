# Getting Started

- [Introduction](#introduction)
- [Installation](#installation)
- [Redacting Logs](#redacting-logs)
- [Your First Redaction](#your-first-redaction)
- [Inspecting a Redaction](#inspecting-a-redaction)
- [The Fluent Builder](#the-fluent-builder)
- [Profiles](#profiles)
    - [The Shipped Profiles](#the-shipped-profiles)
    - [Strategies](#strategies)
- [Exceptions](#exceptions)
- [Validating Your Configuration](#validating-your-configuration)
- [Next Steps](#next-steps)

## Introduction

Redactor takes a value, a string, an array, an object, and returns a copy with the sensitive parts replaced. It finds them three ways: by the name of the key a value sits under, by what the value looks like, and by where it lives in the payload. What replaces a detected value is decided separately, so the same email address can become `[REDACTED]` in one log channel and a stable pseudonym in another.

The package registers a service provider and a facade automatically. Nothing else runs until you ask it to.

## Installation

Install the package with Composer:

```bash
composer require kirschbaum-development/redactor
```

Then publish the configuration file:

```bash
php artisan vendor:publish --tag=redactor-config
```

This writes `config/redactor.php`. You can run the package without publishing it; the defaults described in [Configuration](configuration.md) apply. Publish it when you want to add your own rules or profiles.

Redactor requires PHP 8.3, 8.4 or 8.5 and Laravel 12 or 13.

## Redacting Logs

The most common boundary is the log. Add the tap to any channel in `config/logging.php`:

```php
'channels' => [
    'stack' => [
        'driver' => 'stack',
        'channels' => explode(',', env('LOG_STACK', 'single')),
        'ignore_exceptions' => false,
        'tap' => [Kirschbaum\Redactor\Logging\RedactorTap::class],
    ],
],
```

`RedactorTap` pushes a Monolog processor onto the channel. The processor redacts each record's message, context and extra, then leaves the channel's own formatter alone, so a channel that writes JSON keeps writing JSON.

Append a profile name after a colon when a channel needs something other than the default profile:

```php
'audit' => [
    'driver' => 'daily',
    'path' => storage_path('logs/audit.log'),
    'tap' => [Kirschbaum\Redactor\Logging\RedactorTap::class.':strict'],
],
```

Redaction in the log path never throws. If a profile is misconfigured or a strategy fails on unexpected input, the record's content is replaced rather than emitted and logging carries on. See [Boundaries](boundaries.md#log-channels) for the formatter alternative and what happens to exceptions and other opaque objects.

## Your First Redaction

Call `redact()` on the facade with anything you are about to emit:

```php
use Kirschbaum\Redactor\Facades\Redactor;

$redacted = Redactor::redact([
    'user_id' => 123,
    'password' => 'secret123',
    'api_key' => 'sk-1234567890abcdef1234567890abcdef12345678',
    'email' => 'user@example.com',
]);

// [
//     'user_id' => 123,           // safe key: preserved
//     'password' => '[REDACTED]', // blocked key
//     'api_key' => '[REDACTED]',  // blocked key (*key*)
//     'email' => '[REDACTED]',    // blocked key
//     '_redacted' => true,        // marker, on by default
// ]
```

Inside a string, only the sensitive span is replaced. The text around it survives:

```php
Redactor::redact('User bob@example.com placed order 123');

// 'User [REDACTED] placed order 123'
```

Pass a profile name as the second argument to use something other than the default profile:

```php
Redactor::redact($data, 'strict');
```

Objects are handled too. A Laravel model or anything with a `toArray()` method is walked through that; other objects are walked through their JSON form. Throwables, `DateTimeInterface`, `DateTimeZone`, enums and closures pass through untouched, since taking them apart would destroy them, though key rules still apply to the key they sit under.

## Inspecting a Redaction

When you need to know whether anything matched, call `inspect()` instead of reading the `_redacted` marker back out of the payload:

```php
$result = Redactor::inspect($data);

$result->value;        // the redacted payload
$result->wasRedacted;  // bool
$result->redactedKeys; // ['password', 'api_key', 'email']
$result->findings;     // an array of MatchFinding
```

Each `MatchFinding` carries the rule that fired, the entity it found, the key, a byte offset and length into the value you passed, and a confidence score with the signals behind it:

```php
foreach ($result->findings as $finding) {
    $finding->rule;         // 'email'
    $finding->entity();     // 'email'
    $finding->key;          // 'email'
    $finding->offset;       // 0
    $finding->length;       // 16
    $finding->confidence;   // a Confidence, or null for a blocked key
}
```

`RedactionResult` and `MatchFinding` are both `Arrayable` and `JsonSerializable`. The array form of a finding omits the matched text, so a result can be logged without becoming the leak it reports.

`inspect()` also takes a third argument, `$mark`, which overrides the profile's `mark_redacted` setting for one call:

```php
Redactor::inspect($data, 'default', mark: false)->value;
```

## The Fluent Builder

`Redactor::profile()` returns a `PendingRedaction` you can configure before running it:

```php
Redactor::profile('strict')->redact($data);

Redactor::profile('observability')->withoutMarkers()->inspect($data);

Redactor::profile('audit')
    ->when($verbose, fn ($redaction) => $redaction->withMarkers())
    ->redact($data);
```

The builder offers:

| Method | Effect |
| --- | --- |
| `profile(?string $profile)` | Use the given profile, or `null` for the default. |
| `withMarkers()` | Write the `_redacted` markers into the payload, whatever the profile says. |
| `withoutMarkers()` | Never write the markers. |
| `redact(mixed $content)` | Redact and return the value. |
| `inspect(mixed $content)` | Redact and return a `RedactionResult`. |
| `redactSafely(mixed $content)` | Redact without ever throwing. |

Both the redactor and the pending redaction are `Conditionable` and `Macroable`, so `when()` and `unless()` work as they do elsewhere in Laravel, and you can add your own methods. See [Extending](extending.md#macros).

## Profiles

A profile is one complete redaction configuration: which strategies run and in what order, which keys are safe or blocked, which patterns to look for, and what to do with what is found. Profiles live under `profiles` in `config/redactor.php`, and every entry point accepts a profile name.

Profiles exist because the right amount of redaction depends on where the data is going. An audit log wants everything gone; an application log wants values pseudonymised so you can still count users; a file scan wants content rules only, since there are no keys to match.

You can list and check profiles at runtime:

```php
Redactor::profiles();             // ['default', 'strict', 'file_scan', 'observability', 'performance']
Redactor::hasProfile('audit');    // false
Redactor::strategies('strict');   // the resolved strategy chain
```

### The Shipped Profiles

| Profile | Intended for | What makes it different |
| --- | --- | --- |
| `default` | Application logs and general use | Every strategy, the shared credential and identity rules, entity recognition present but inert, cards partially masked. |
| `strict` | Audit trails and sensitive contexts | More blocked keys (`phone`, `address`, `ip`, `name`, `username`), IPv4 and UUID patterns, entropy threshold 4.0 over 15 characters, `max_value_length` 1000, non-redactable objects redacted. |
| `observability` | Logs you still need to reason about | Pseudonymises emails, phones, IPs and cards with stable surrogates instead of redacting them; `min_confidence` 0.4; no markers. |
| `file_scan` | `redactor:scan` | No key strategies at all; adds labelled rules such as `api_key_generic`, `aws_secret_key`, `base64_key` and `password_assignment`. |
| `performance` | High-throughput paths | Key rules, known secrets and two patterns (`email`, `simple_token`); no size limits, no entropy, no markers. |

The `default`, `strict`, `observability` and `file_scan` profiles share the same credential and identity rules. They are defined once at the top of the config file and spread into each profile, so a credential one profile catches is caught by the others. [Configuration](configuration.md#the-shipped-profiles-compared) compares every setting side by side.

### Strategies

A profile lists its strategies in the order they run. The shipped ones are:

| Strategy | Role |
| --- | --- |
| `SafeKeysStrategy` | Preserves values under safe keys, subtree included, and stops the walk. |
| `BlockedKeysStrategy` | Redacts values under blocked keys. |
| `LargeObjectStrategy` | Replaces arrays and objects with more items than `max_object_size`. |
| `LargeStringStrategy` | Truncates strings over `max_value_length`, keeping and scanning the head. |
| `KnownSecretsStrategy` | Finds the application's own credentials wherever they appear verbatim. |
| `RegexPatternsStrategy` | Finds spans by pattern. |
| `ShannonEntropyStrategy` | Finds tokens random enough to be a credential. |
| `EntityRecognitionStrategy` | Asks a named entity recogniser about free text. Inert until `recognition.enabled` is true. |

The chain stops at the first strategy that replaces a value outright. The last four are *detectors*: they report what they found and where, change nothing, and once every detector has seen the value the context resolves the reports and rewrites the string once. [Rules](rules.md#how-detections-are-resolved) explains what follows from that.

## Exceptions

Everything the package throws implements `Kirschbaum\Redactor\Exceptions\RedactorException`, so one `catch` covers all of it:

| Exception | Extends | Thrown when |
| --- | --- | --- |
| `ConfigurationException` | `InvalidArgumentException` | A profile or rule is misconfigured. The message names the config path. |
| `ProfileNotFoundException` | `ConfigurationException` | The requested profile is not configured. |
| `PseudonymizationKeyException` | `RuntimeException` | No key strong enough to pseudonymise with could be produced. |
| `GitException` | `RuntimeException` | The scanner asked git and git could not answer. |

`redact()` and `inspect()` throw. `redactSafely()` does not: it catches everything, logs a warning through the package's re-entrancy guard, and returns the profile's replacement string followed by ` (redaction failed)`. That is the method the log processor, the middleware and the stream redactor use, since a throw inside the pipeline that reports errors would take the error with it.

## Validating Your Configuration

A broken profile throws the first time something uses it, which in the log path means it is replaced rather than emitted. Find out at deploy time instead:

```bash
php artisan redactor:validate
```

The command resolves every profile, builds its strategy chain, checks that no key is listed as both safe and blocked, and runs every rule's samples through the real detection path. It exits non-zero if anything fails. See [Testing](testing.md#validating-profiles).

## Next Steps

- [Boundaries](boundaries.md) covers every place data leaves an application and the adapter for each.
- [Rules](rules.md) explains how to write patterns that catch what you mean and nothing else.
- [Operators and Pseudonymisation](operators-and-pseudonymisation.md) shows how to keep logs joinable after redaction.
