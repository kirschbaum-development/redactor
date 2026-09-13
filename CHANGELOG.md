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
- **Provider credentials in every profile.** JWTs, bearer tokens, PEM private
  key blocks, credential URLs for any scheme, and AWS, GitHub, Stripe, Slack,
  OpenAI, Anthropic, Google and SendGrid keys were only recognised by the
  `file_scan` profile; the `default`, `strict` and `observability` profiles
  relied on entropy, which misses a 20-character AWS key outright and a GitHub
  token by a tenth of a bit. The rules are defined once at the top of the
  config and spread into each profile.
- **Identity patterns that match what people actually write.** Non-ASCII
  emails, IBANs in the spaced form banks print, international and E.164 phone
  numbers. A bare ten-digit run is only a phone number next to a label such as
  `phone` or `tel`; before, every Unix timestamp and ten-digit order number in
  a log message was redacted as one. The `strict` profile's phone rule, which
  matched any run of seven digits and spaces, is gone.
- **Pattern `keywords` and `min_length`.** A rule can name literals that must
  appear in the value before its pattern is tried - a prefilter for cost, since
  `['@']` keeps the email regex off almost every string in a payload, and for
  precision, so a bare ten-digit run needs a `phone` label somewhere before it
  is believed - and the shortest text it could match, so a shorter value skips
  the rule with one integer compare. Every shipped rule declares both where
  they apply.
- **Allow-lists.** A profile `allowlist` of literals and regexes that are
  never findings whichever detector reports them, and a per-rule `allow` list
  scoped to one rule. Checked after detection, so patterns stay as strong as
  written. An entry that cannot be evaluated allows nothing.
- **Dictionary rules.** A pattern can be a `words` list - codenames, customer
  names, anything no regex expresses - compiled into one whole-word,
  case-insensitive alternation, longest first.
- **Known secrets.** `known_secrets.values` and `known_secrets.config` register
  the application's own credentials - `app.key` by default - so they are
  redacted wherever they appear verbatim, in every profile; the config form
  registers every string under an array key. `Redactor::registerSecret()` adds
  one at runtime. Values under eight characters are refused.
- **`redactor:allow` on a line** suppresses the scanner's findings for that
  line, for the fixture or the documented example that a baseline would also
  accept but without the reason living in a JSON file.
- **Entity recognition.** `EntityRecognitionStrategy` asks a named entity
  recogniser about free text and feeds what it finds - people, places,
  organisations - through the same overlap resolution, confidence floor and
  operators as every other detector. The built-in driver speaks Presidio's
  `/analyze` contract; `Redactor::registerRecognizer()` adds others. Gated to
  prose-shaped values within a length band, to the labels asked for and the
  score threshold set; every span's character offsets are converted and
  verified against the value before replacement; failures degrade to
  rules-only and a circuit breaker stops a dead sidecar being asked on every
  log line. Present in the shipped profiles and inert until enabled.
- **Git-aware scanning.** `redactor:scan --staged`, `--diff=<ref>` and
  `--history[=<range>]` scan only the lines a change adds, on their real line
  numbers, with the commit that added them for history. A secret removed by a
  later commit is still found. Paths given with a git mode act as a pathspec;
  exclude patterns still apply.
- **`redact` middleware.** `->middleware('redact:profile')` redacts a
  response before it is sent: JSON as data, text as text, files untouched,
  never writing `_redacted` markers into a payload, failing closed to a 500.
- **MCP and AI adapters.** `Mcp\RedactsResponses` on a Laravel MCP server
  redacts tool results, structured content, resource reads, prompt messages,
  streamed output and errors over any transport; `Ai\RedactPrompt` middleware
  redacts a prompt before the provider and resolves tokens in the answer. Both
  SDKs are suggested, not required.
- **`RedactionPerformed` event** with the profile, keys and counts per rule
  and entity, never a value; a throwing listener cannot break redaction.
- **Reversible tokens.** The `tokenize` operator replaces a value with a
  stable, model-friendly token (`tok_email_k4m9rp2xzq`) and keeps the original
  encrypted in the cache for a TTL; `Redactor::detokenize()` exchanges known
  tokens back and leaves unknown ones alone. `Tokenization\TokenStore` is the
  contract for another backing store.
- **Streaming redaction.** `Streaming\StreamRedactor` redacts chunk by chunk
  with a hold-back window, so a secret split across two chunks is still caught;
  `through()` for iterables of chunks, `wrap()` for echoing callbacks,
  `response()` for a streamed response. The `redact` middleware applies it to
  streamed responses automatically.
- **`nullify` operator.** Replaces a value with null so a typed field keeps
  its type and its key; inside a string it deletes the span.
- **`Redactor::fake()`** for application test suites: a redactor that still
  redacts but records every call, with `assertNeverEmitted()`,
  `assertRedacted()`, `assertFinding()`, `assertProfileUsed()` and friends,
  so a test can prove a secret never left rather than hope it did not.
- **Self-testing rules.** A rule carries `samples` and `counter_samples`, and
  `redactor:validate` runs them through the real detection path - keywords,
  min_length, validators and allow-lists applied - failing on a rule that no
  longer detects a sample or detects a counter-sample. Every shipped rule has
  both.
- **Ruleset fingerprint.** A digest of the rules a scan ran, reported in JSON
  and SARIF and recorded in baselines; a baseline made under a different
  ruleset is warned about.
- **Decoding in the scanner.** Base64 tokens, percent-encoded runs and
  JSON-escaped lines are decoded one layer deep and scanned; a finding names
  the encoding and its excerpt comes from the decoded, redacted text.
  `scan.decode` switches it off.
- **JUnit output** (`--output=junit`), a publishable pre-commit hook and a
  GitHub workflow (`vendor:publish --tag=redactor-ci`) that scans pull
  requests over their base and uploads SARIF.
- **`Detector` contract.** Anything that can report `Detection`s against a
  string - a regex, an entropy measure, a recogniser model in another process
  - plugs into the same resolution and operator pipeline.

### Performance

- Compiled key matchers are resolved once with the profile instead of being
  looked up per call. KeyMatcher memoises on the pattern list, so finding the
  cached matcher meant building an implode() of every configured key on every
  check - 0.203us against the 0.050us match it was avoiding, making the cache
  cost four times what it saved.
- Entropy analysis is skipped for values shorter than min_length. A byte count
  is an upper bound on a character count, so the check can only skip work that
  was provably going to find nothing; most values in a log payload are well
  under the threshold. Measured at 40x over a realistic value set.
- Tokenising uses the non-/u patterns for ASCII subjects. The /u modifier makes
  PCRE validate the whole subject as UTF-8 on every call: 40us against 12us to
  split a 2.2KB string. The choice is made per subject, because dropping /u for
  non-ASCII input would join tokens rather than merely run faster.
- Matched spans are rewritten in a single left-to-right pass. substr_replace
  builds a whole new string per replacement, so a value with several matches
  copied it several times.
- An unchanged subtree is returned as it arrived rather than rebuilt, so a
  payload that redacts to nothing costs a walk and no copy.
- Net effect, measured on PHP 8.5.8 with opcache and the PCRE JIT off
  (production is faster in absolute terms): a 31-leaf request payload through
  the `default` profile costs 68us against 48us before this work, with the
  profile now running 20 detection rules instead of 6, scrubbing the
  application's own secrets and scoring entropy hits; a Monolog record through
  the processor 84us against 59us; a 1 MB free-text subject 24ms against 38ms
  with peak memory down from 10 MB to 1 MB; a 64 KB subject with twenty
  secrets 2.8ms against 4.7ms. Scaling is linear in both dimensions. A
  profile that wants the old cost back removes the rules it does not need.
- The pseudonymizer is resolved lazily by the operators that need it. Routing
  blocked keys through operators had made every redaction with a blocked key
  derive an HMAC key it then never used.
- Each rule asks a capture-free `preg_match()` before `preg_match_all()` with
  offsets, since most rules do not match most values, and skips the subject
  outright when it is shorter than the rule's `min_length`.
- The entropy detector asks PCRE for tokens of at least `min_length` rather
  than every token, since shorter ones can never qualify. A 1 MB subject of
  ordinary words held ~180,000 [token, offset] pairs - ten times the input -
  and now holds none.
- Resolved profiles are cached and invalidated by comparing the raw config, so
  `fromConfig()` no longer revalidates every pattern and recompiles the path
  trie on every redaction: 0.2285ms -> 0.0011ms for a profile with 200 path
  rules, and flat with rule count rather than linear.

Hardening pass across correctness, security, performance and packaging. Each
item below is one commit, with tests.

### Changed - behaviour you should read before upgrading

- **Detections are collected and the value rewritten once.** The regex and
  entropy strategies no longer rewrite the string as they go; they report, the
  context resolves overlaps and applies the confidence floor, and the original
  value is rewritten in one pass. Of two overlapping reports the higher score
  wins, then the rule listed first. Findings for a `preserve` operator are now
  reported without marking the payload redacted.
- **The pseudonymisation salt is shared across profiles.** It defaulted to the
  profile name, so two channels on different profiles produced different
  surrogates for the same user and could not be joined. Set a profile's own
  `pseudonymization.salt` to break correlation on purpose.
- **Blocked keys go through operators.** The key name is the entity, so
  `operators.email` applies to a value under an `email` key. Findings from a
  blocked key now carry the value they matched and a certain score.
- **Long strings are truncated and scanned, not replaced.** A value over
  `max_value_length` keeps its head, which the remaining strategies still
  inspect, followed by `[REDACTED] (String truncated: 65536 characters, 5000
  kept)`. The values most often over the limit in a Laravel log are stack traces
  and request bodies, and replacing them wholesale destroyed exactly what the
  reader needed. `large_string_behavior: redact` restores the old behaviour.
- **Throwables, dates, enums and closures pass through the walk untouched.** A
  Throwable has no public properties and encoded to `{}`, so `['exception' =>
  $e]` reached the formatter as `[]` and the stack trace was lost; a Carbon
  instance was exploded into its `toArray()` components. Key rules still apply
  to these values, so `['secret' => $enum]` is still redacted.
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

- A surrogate written by the regex strategy was re-detected by the entropy
  strategy that ran next - it has the same shape and entropy as the value it
  replaced - and turned into `[REDACTED]`, destroying the joinability the
  profile paid for. Detectors now all see the original value.
- The scanner reported the wrong column for the second finding on a line: each
  rule measured its offsets against the string the previous rule had already
  rewritten. Offsets are now always against the original.
- Entropy detections bypassed `operators`, `min_confidence` and confidence
  scoring entirely, and the scanner ranked their null score as `high` - above a
  Luhn-validated card. They now carry a score and go through the same policy.
- On PHP 8.5 every object walked raised three `SplObjectStorage` deprecations,
  which Laravel logs - and a log record raised from inside a log tap is redacted,
  which raises them again. Active objects are now tracked by `spl_object_id`.
- `operators.default` had no effect on anything found by a pattern. A rule can
  always produce an operator from its `mode`, which defaults to replace, and
  that default was treated as a choice - so it outranked the profile default
  and made the setting silently unreachable. Only a rule that actually
  configured an operator or a non-default mode now outranks it.
- A path pattern that is purely numeric - `'0' => 'redact'`, or `items.0`
  written as a key - crashed. PHP turns a numeric array key into an integer,
  which reached a parameter typed as string.

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
