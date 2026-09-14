# Upgrading

- [Introduction](#introduction)
- [Requirements](#requirements)
- [Renamed Classes and Methods](#renamed-classes-and-methods)
- [Removed Methods](#removed-methods)
- [Behaviour Changes](#behaviour-changes)
- [Configuration Keys That Changed Meaning](#configuration-keys-that-changed-meaning)
- [Renamed Rules](#renamed-rules)
- [The Scan Command](#the-scan-command)
- [Checklist](#checklist)

## Introduction

This page covers upgrading from 0.1.0 to the next release. Every rename is listed with its replacement, every behaviour change with what to do about it. The old names are gone rather than deprecated, so an upgrade that compiles is an upgrade that has been done.

If you followed the unreleased `main` branch between 0.1.0 and this release, the interim names it carried, `redactWithMetadata()` among them, are listed too.

## Requirements

| | 0.1.0 | Now |
| --- | --- | --- |
| PHP | 8.3, 8.4 | 8.3, 8.4, 8.5 |
| Laravel | 11, 12 | 12, 13 |

Laravel 11 support is dropped: every 11.x release is flagged by a Packagist security advisory, so Composer's default policy refuses to install any of them.

`spatie/laravel-package-tools` is no longer required; `symfony/finder`, `symfony/process` and `monolog/monolog` are declared directly. `laravel/mcp` and `laravel/ai` are suggested, not required.

## Renamed Classes and Methods

| 0.1.0 | Now | Notes |
| --- | --- | --- |
| `Logging\ReadactFormatter` | `Logging\RedactorFormatter` | Can now wrap an inner formatter: `new RedactorFormatter(new JsonFormatter)`. |
| `Logging\CustomLogTap` | `Logging\RedactorFormatterTap` | Kept for channels that want the formatter. Prefer `Logging\RedactorTap`, which adds a processor and leaves the channel's format alone. |
| `Strategies\RedactionStrategyInterface` | `Strategies\Contracts\Strategy` | Same two methods. |
| `Redactor::getAvailableProfiles()` | `Redactor::profiles()` | |
| `Redactor::profileExists()` | `Redactor::hasProfile()` | |
| `Redactor::getStrategies()` | `Redactor::strategies()` | |
| `Redactor::redactWithMetadata()` (interim) | `Redactor::inspect()` | Returns a `RedactionResult` with `value`, `wasRedacted`, `redactedKeys` and `findings`. |

Update `config/logging.php`:

```php
// 0.1.0
'tap' => [Kirschbaum\Redactor\Logging\CustomLogTap::class],

// Now
'tap' => [Kirschbaum\Redactor\Logging\RedactorTap::class],
```

`RedactorTap` accepts a profile after a colon: `RedactorTap::class.':strict'`.

## Removed Methods

| Removed | Replacement |
| --- | --- |
| `Redactor::addStrategy()` | List the strategy in the profile's `strategies`, or `registerCustomStrategy()`. |
| `Redactor::removeStrategy()` | Remove it from the profile's `strategies`. |
| `Redactor::calculateShannonEntropy()` | `(new ShannonEntropyStrategy)->calculateShannonEntropy($string)`. |
| `Redactor::isCommonPattern()` | `(new ShannonEntropyStrategy)->isCommonPattern($string, $config)`. |

The facade no longer forwards `calculateShannonEntropy()` or `isCommonPattern()`.

## Behaviour Changes

Each of these changes what an existing configuration produces. Read them before upgrading.

**Redaction now replaces the matched span, not the whole value.** `redact('User bob@example.com placed order 123')` returns `'User [REDACTED] placed order 123'` rather than `'[REDACTED]'`. If a rule must condemn the whole value on one match, give it `'mode' => 'full'`; if the intent was "this key is always sensitive", a blocked key or a path rule says so directly.

**Detections are collected and the value rewritten once.** The regex and entropy strategies no longer rewrite the string as they go. They report, the context resolves overlaps and applies the confidence floor, and the original value is rewritten in one pass. Of two overlapping reports the higher score wins, then the rule listed first. A custom strategy that relied on seeing the string *after* the regex strategy rewrote it now sees the original; implement `DetectingStrategy` and report through `$context->collect()` to join the resolution.

**Findings for a `preserve` operator are reported without marking the payload redacted.** A scan profile that only reports no longer sets `wasRedacted`.

**`safe_keys` preserves the entire subtree.** Everything nested under a safe key is emitted untouched. The shipped profiles no longer list `message`, `title`, `url`, `path`, `ip`, `user_agent`, `source` or `target` as safe: all of them are free text or personal data, and with them safe the values were emitted verbatim. `session_id` was listed as both safe and blocked and is now blocked only. If you copied the 0.1.0 lists into your own profile, remove those keys; `redactor:validate` reports any key in both lists.

**Long strings are truncated and scanned, not replaced.** A value over `max_value_length` keeps its head, which the remaining strategies still inspect, followed by `[REDACTED] (String truncated: 65536 characters, 5000 kept)`. Set `'large_string_behavior' => 'redact'` on a profile to restore the old wholesale replacement.

**Throwables, dates, enums and closures pass through the walk untouched.** A Throwable used to encode to `{}` and reach the formatter as `[]`, losing the stack trace; a Carbon instance was exploded into its `toArray()` components. Key rules still apply, so `['secret' => $enum]` is still redacted. If you relied on a date being turned into an array, convert it yourself before redacting.

**Blocked keys go through operators.** The key name is the entity, so `operators.email` applies to a value under an `email` key. Findings from a blocked key now carry the value they matched and a certain score. A blocked key holding an array, boolean or null still collapses to the replacement string.

**The pseudonymisation salt is shared across profiles.** It used to default to the profile name, so two channels on different profiles produced different surrogates for the same user and could not be joined. Surrogates produced before the upgrade will not match surrogates produced after it. Set a profile's own `pseudonymization.salt` to break correlation on purpose.

**Monolog integration moved to a processor.** `RedactorTap` pushes `RedactorProcessor`, which redacts message, context and extra without touching the channel's output format. Channels that used `CustomLogTap` had their formatter replaced with the package's own line format; with `RedactorTap` they keep the formatter they were configured with, so a channel whose output was the package's format will change format. Use `RedactorFormatterTap` to keep the old behaviour.

**Scan findings are structured.** Each finding carries rule, line, column and a redacted excerpt instead of one opaque `full_content_redacted` record per file. Anything parsing the JSON output needs updating. See [The Scan Command](#the-scan-command).

**Invalid configuration now throws** with the offending path named, instead of silently falling back to a default. A value that used to be ignored, such as a non-numeric `max_depth`, now fails the profile. Run `php artisan redactor:validate` before deploying.

**Redaction metadata no longer corrupts the payload.** `_redacted` is never added to a list, since a string key would turn a JSON array into an object, and a caller's own `_redacted` key is never overwritten. If you read the marker to know whether anything matched, use `inspect()->wasRedacted` instead.

**Documented environment variables now take effect.** `REDACTOR_MAX_OBJECT_SIZE` was silently ignored and `REDACTOR_SCAN_MAX_FILE_SIZE` crashed the scan command. If either is set in your environment, it now applies.

**Scanner exclude patterns now work.** `vendor/*` and `node_modules/*` matched nothing in 0.1.0, so every dependency was scanned. They now match, and binary and gitignored files are skipped too. A scan that used to report findings in `vendor/` will stop.

**PCRE failures fail closed.** A pattern that errors, on the backtrack limit or bad UTF-8, used to let the value through; it now replaces the value and logs the rule. A rule that was silently never matching may now redact everything it is given, which `redactor:validate` and the rule's samples will surface.

**Entropy is measured per character, not per byte, and can be judged per alphabet.** Non-ASCII text scores lower than before, and the shipped profiles judge hex against 3.0 and base64 against 4.5 through `charset_thresholds`. Entropy detections now carry a score and go through `operators` and `min_confidence`, which they bypassed before.

**Checksum validators reject values of the right shape that cannot be real.** The shipped `credit_card`, `ssn` and `iban` rules now validate, so an order number that happens to have 16 digits is left alone.

**Recursion is depth-bounded and cycle-aware.** A self-referencing `toArray()` used to exhaust memory; it is now replaced at `max_depth` or on the first repeated object.

**The logging path never throws.** A bad profile no longer takes the channel down, and diagnostics cannot re-enter the logger that raised them.

**`RedactorFormatter::formatBatch()` formats every record.** It used to return only the first.

## Configuration Keys That Changed Meaning

| Key | Before | Now |
| --- | --- | --- |
| `safe_keys` | Preserved the scalar; documented wildcards did not work. | Preserves the whole subtree; wildcards work. |
| `patterns.<name>` | A regex whose match condemned the whole value. | A regex whose match is replaced in place, or a full rule with `mode`, `keep`, `mask_character`, `capture`, `validator`, `entity`, `confidence`, `operator`, `keywords`, `min_length`, `samples`, `counter_samples`, `allow` or `words`. |
| `max_value_length` | Replaced the whole string. | Truncates and scans the head; see `large_string_behavior`. |
| `mark_redacted` | Wrote `_redacted` into any array, lists included, overwriting an existing key. | Associative arrays only, never overwrites, never written into HTTP responses or MCP structured content. |
| `shannon_entropy.threshold` | Judged every token, measured per byte. | Judged only tokens whose alphabet has no `charset_thresholds` entry, measured per character. |
| `scan.exclude_patterns` | Matched basenames only. | Matches basename and relative path; `dir/*` prunes the directory. |
| `non_redactable_object_behavior` | Unchanged in meaning, but Throwables and dates were walked like any other object and lost their content. | Throwables, dates, enums and closures pass through whole; the setting applies only to objects that can be neither `toArray()`'d nor JSON-encoded. |

New keys, all optional with safe defaults: `large_string_behavior`, `max_depth`, `min_confidence`, `operators`, `paths`, `allowlist`, `known_secrets`, `recognition`, `shannon_entropy.charset_thresholds`, per-profile `pseudonymization`; and at the top level `pseudonymization`, `tokenization`, `events`, `scan.skip_binary`, `scan.respect_gitignore`, `scan.window_lines`, `scan.overlap_lines`, `scan.decode`, `scan.verification` and `scan.baseline`. See [Configuration](configuration.md).

## Renamed Rules

The shipped patterns were reorganised into two shared lists spread into every profile. If you reference rule names, in a baseline, a listener on `RedactionPerformed`, or `assertFinding()`, these changed:

| 0.1.0 rule | Profile | Now |
| --- | --- | --- |
| `phone_simple` | `default`, `file_scan` | `phone_formatted`, `phone_e164` and `phone_bare` in every profile. |
| `phone` | `strict` | Removed. It matched any run of seven digits and spaces. |
| `api_key_stripe` | `file_scan` | `stripe_key`, in every profile. |
| `jwt_token` | `file_scan` | `jwt`, in every profile. |
| `jwt` | `strict` | `jwt`, with the shared pattern. |
| `aws_secret_key` | `file_scan` | Still `file_scan` only, but now requires a label such as `aws_secret_access_key =` before it; it used to match any 40-character alphanumeric run. |
| `url_with_auth` | all | Same name; any scheme, and only the password is replaced. |

Credential rules that were `file_scan` only in 0.1.0, or absent altogether (`bearer_token`, `private_key_block`, `slack_token`, `anthropic_key`, `openai_key`, `google_api_key`, `sendgrid_key`), now run in `default`, `strict` and `observability` as well. Expect more findings from those profiles.

## The Scan Command

`redactor:scan` gained `--output=sarif`, `--output=junit`, `--staged`, `--diff`, `--history`, `--min-confidence`, `--verify`, `--baseline` and `--update-baseline`. The `--output=json` structure changed: each file object now carries `ruleset`, `status`, `findings_count` and a `findings` array of structured findings. See [Scanning](scanning.md#output-formats).

Baselines did not exist in 0.1.0, so there is nothing to migrate; generate one with `--update-baseline` after upgrading.

## Checklist

1. Update `composer.json` to PHP 8.3+ and Laravel 12 or 13, and remove any direct dependency on the package's old transitive requirements.
2. Replace `CustomLogTap` with `RedactorTap` in `config/logging.php`, or with `RedactorFormatterTap` if the channel must keep the package's line format.
3. Replace `ReadactFormatter` with `RedactorFormatter` and `RedactionStrategyInterface` with `Strategies\Contracts\Strategy`.
4. Replace `getAvailableProfiles()`, `profileExists()` and `getStrategies()` with `profiles()`, `hasProfile()` and `strategies()`; replace `redactWithMetadata()` with `inspect()`.
5. Replace `addStrategy()` and `removeStrategy()` with profile configuration; call `calculateShannonEntropy()` and `isCommonPattern()` on `ShannonEntropyStrategy`.
6. Re-publish the config (`vendor:publish --tag=redactor-config --force`) or merge the new keys by hand, and remove free-text keys from any `safe_keys` list you copied.
7. Run `php artisan redactor:validate`.
8. If you export logs elsewhere, note that surrogates change once because the salt no longer includes the profile name.
9. Run `php artisan redactor:scan --update-baseline` if the scanner should start green, and publish the hook and workflow with `vendor:publish --tag=redactor-ci`.
