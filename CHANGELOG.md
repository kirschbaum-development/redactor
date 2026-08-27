# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

Hardening pass across correctness, security, performance and packaging. Each
item below is one commit, with tests.

### Changed - behaviour you should read before upgrading

- **Redaction now replaces the matched span, not the whole value.**
  `redact('User bob@example.com placed order 123')` returns
  `'User [REDACTED] placed order 123'` rather than `'[REDACTED]'`. (R-01)
- **`safe_keys` preserves the entire subtree**, and the shipped profiles no
  longer list `message`, `title`, `url`, `path`, `ip`, `user_agent`, `source` or
  `target` as safe - all of them are free text or personal data, and with them
  safe the values were emitted verbatim. `session_id` was listed as both safe
  and blocked; it is now blocked only. (R-02)
- **Monolog integration moved to a processor.** Use
  `Logging\RedactorTap` / `Logging\RedactorProcessor`, which redact message,
  context and extra without touching the channel's output format.
  `ReadactFormatter` still works and can now wrap an inner formatter. (R-06)
- **Scan findings are structured**: rule, line, column and a redacted excerpt,
  instead of one opaque `full_content_redacted` record per file. (R-10)
- **Removed** `Redactor::addStrategy()`, `removeStrategy()`,
  `calculateShannonEntropy()` and `isCommonPattern()`. The two useful ones are
  now public on `ShannonEntropyStrategy`. (R-20)
- Invalid configuration now throws with the offending path named, instead of
  silently falling back to a default. (R-09)

### Fixed - correctness and security

- Recursion is depth-bounded and cycle-aware. A self-referencing `toArray()`
  used to exhaust memory and kill the process. (R-03)
- The logging path never throws. A bad profile no longer takes the channel down,
  and diagnostics cannot re-enter the logger that raised them. (R-04)
- Scanner exclude patterns work. `vendor/*` and `node_modules/*` were passed to
  `Finder::notName()`, which matches basenames, so they matched nothing and
  every dependency was scanned. Binary files and gitignored files are skipped
  too. (R-05)
- Redaction metadata no longer corrupts the payload: a list stays a list, and a
  caller's own `_redacted` key is not overwritten. Prefer
  `redactWithMetadata()`. (R-07)
- `safe_keys` supports the wildcards the README has always documented. (R-08)
- Documented environment variables take effect. `REDACTOR_MAX_OBJECT_SIZE` was
  silently ignored and `REDACTOR_SCAN_MAX_FILE_SIZE` crashed the scan
  command. (R-09)
- PCRE failures fail closed. `preg_match()` returning `false` was read as
  "no match", so an errored pattern let the value through. (R-15)
- Entropy is measured per character, not per byte, and can be judged per
  alphabet. The `aws_secret_key` pattern no longer matches any 40-character
  alphanumeric run. (R-16)
- Checksum validators (`luhn`, `iban`, `ssn`) reject values of the right shape
  that cannot be the real thing. (R-17)
- `mergeConfigFrom()` runs in `register()`, not `boot()`. (R-14)
- `ReadactFormatter::formatBatch()` formats every record; it used to return only
  the first, so batching handlers dropped the rest. (R-06)

### Added

- `Redactor::redactWithMetadata()` returning a `RedactionResult`. (R-07)
- `Redactor::redactSafely()`, which never throws. (R-04)
- `php artisan redactor:validate` - resolves every profile and fails on the
  broken ones, including keys listed as both safe and blocked. (R-04, R-02)
- Pattern rules: `mode` (replace/mask/partial/remove/full), `keep`,
  `mask_character`, `capture` and `validator`. (R-01, R-16, R-17)
- `max_depth` and `shannon_entropy.charset_thresholds` profile settings.
  (R-03, R-16)
- `redactor:scan --output=sarif` for GitHub code scanning, and
  `--baseline` / `--update-baseline` so CI fails only on new findings. (R-10)

### Performance

- Blocked-key matching compiles its pattern list once instead of rebuilding a
  regex per key per call: 1.223 us -> 0.288 us per check. (R-12)
- Nested nodes are dispatched through the strategy chain once rather than
  twice. (R-13)
- `Redactor` and `Scanner` are container singletons, so the strategy cache
  survives. (R-11)
- Net effect on the default profile: ~15,000 -> ~21,000 redactions/sec, while
  doing strictly more work than before.

### Packaging and CI

- PHP 8.5 supported and in the test matrix. (R-21)
- `Tests\` no longer ships in the production autoload; `.gitattributes` keeps
  development files out of the dist archive. (R-18)
- Dropped the unused `spatie/laravel-package-tools` requirement and declared
  `symfony/finder` and `monolog/monolog`, which the package uses directly. (R-19)
- Coverage floor, Infection mutation testing, a performance regression suite,
  and `failOnWarning`/`failOnRisky`/`failOnDeprecation` in phpunit.xml. (R-24)
- Pint passes. `LICENCE.md` renamed to `LICENSE.md` so the README links and the
  Packagist licence detection work. (R-22, R-23)

## v0.1.0 - 2025-06-19

Redactor v0.1.0
