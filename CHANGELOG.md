# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added - capability

- **Path rules.** `'request.headers.authorization' => 'redact'` names a location
  outright, with `*` for one level, `**` for any depth and `users[*].token` for
  lists. Checked first and, when one matches, instead of everything else - no key
  matching, no pattern scanning, no walk below the node. Compiled once into a
  trie walked in lockstep with the payload, so 200 rules cost about what one
  does. The more specific pattern always wins, so declaration order never
  matters.
- **Operators, separated from detection.** `redact`, `mask`, `partial`,
  `remove`, `hash`, `surrogate` and `preserve`, chosen per entity rather than
  per pattern. Register your own with `Redactor::registerOperator()`. Detection
  now says only what was found and where; what happens to it is a separate,
  configurable decision.
- **Deterministic pseudonymisation.** `surrogate` and `hash` replace a value
  with a stable stand-in, so the same email always yields the same output and
  redacted logs stay joinable - counts, joins and traces all survive. Surrogates
  preserve shape: an email stays a valid email, a card stays Luhn-valid with its
  BIN, and anything else keeps its character classes and separators. One-way
  (HMAC, not encryption); falls back to plain redaction when no key is
  available, rather than emitting an unkeyed stand-in that would look joinable
  and silently not be.
- **Confidence scoring.** Detections carry a score and the signals behind it, so
  a profile is tuned with one `min_confidence` number instead of by weakening
  patterns. A passing checksum or a nearby credential keyword raises the score,
  which lets the same pattern be filtered as noise alone and reported when
  corroborated. Surfaced in scan output, mapped onto SARIF levels, and filterable
  with `--min-confidence`.
- **Streaming file scanning.** Files are read as overlapping windows of lines,
  so memory stays flat whatever the size. Windows overlap so a secret spanning a
  boundary is still found; duplicates are dropped by fingerprint.
- **Credential verification.** `--verify` asks each provider whether a detected
  credential is live, ranking confirmed-live findings above everything else.
  Off unless config enables it, the run passes `--verify`, and the provider is
  on an explicit allowlist - and never reachable from the redaction path at all.
  The command names every host before contacting any. The secret never reaches
  a finding, so it cannot escape through JSON, SARIF or a baseline.
- **`observability` profile**, set up to pseudonymise rather than redact.

### Performance

- Resolved profiles are cached and invalidated by comparing the raw config, so
  `fromConfig()` no longer revalidates every pattern and recompiles the path
  trie on every redaction: 0.2285ms -> 0.0011ms for a profile with 200 path
  rules, and flat with rule count rather than linear.

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
- Coverage floor of 90% (CI reports 95.3%), a performance regression suite run
  without coverage instrumentation, and
  `failOnWarning`/`failOnRisky`/`failOnDeprecation` in phpunit.xml. (R-24)
- Mutation testing (Pest's built-in mutator) is available locally via
  `composer mutate`. It is not run in CI: two consecutive runs over an
  identical 1,557-mutant set scored 70.6% and 66.7% with only added passing
  tests between them, so the number is not stable enough to act on
  automatically. (R-24)
- Boundary tests for every redaction threshold - max_object_size,
  max_value_length, the entropy threshold and min_length, max_depth, partial
  mode's `keep`, and the Luhn length window. Mutation testing surfaced these:
  the thresholds were covered but never their edges, so `>` could become `>=`
  without a test noticing. On a redactor an off-by-one there is the difference
  between catching a secret and emitting it.
- **Laravel 11 support dropped**; the package now requires
  `illuminate/support ^12.0|^13.0`. Every 11.x release is flagged by a
  Packagist security advisory, so Composer's default policy refuses to install
  any of them, making the declared support unusable in practice.
- **Laravel 13 supported** and in the test matrix. `symfony/finder` widened to
  `^7.0|^8.0`, which Laravel 13 requires.
- Dropped the unused `pestphp/pest-plugin-laravel` dev dependency. It was the
  only thing pinning the test toolchain to a single Laravel major, and no test
  used it - `$this->artisan()` comes from Testbench.
- The test matrix no longer uses `fail-fast`.
- Pint passes. `LICENCE.md` renamed to `LICENSE.md` so the README links and the
  Packagist licence detection work. (R-22, R-23)

## v0.1.0 - 2025-06-19

Redactor v0.1.0
