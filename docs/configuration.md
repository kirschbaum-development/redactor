# Configuration

- [Introduction](#introduction)
- [Top-Level Keys](#top-level-keys)
    - [default_profile](#default_profile)
    - [scan](#scan)
    - [pseudonymization](#pseudonymization)
    - [tokenization](#tokenization)
    - [events](#events)
    - [profiles](#profiles)
    - [custom_strategies](#custom_strategies)
- [Profile Keys](#profile-keys)
    - [Strategies and Keys](#strategies-and-keys)
    - [Rules](#rules)
    - [Operators and Confidence](#operators-and-confidence)
    - [Output and Limits](#output-and-limits)
    - [shannon_entropy](#shannon_entropy)
    - [recognition](#recognition)
    - [known_secrets](#known_secrets)
    - [pseudonymization (per profile)](#pseudonymization-per-profile)
- [The Shared Pattern Lists](#the-shared-pattern-lists)
- [The Shipped Profiles Compared](#the-shipped-profiles-compared)
- [Environment Variables](#environment-variables)
- [How Values Are Validated](#how-values-are-validated)

## Introduction

All of the package's configuration lives in `config/redactor.php`. Publish it with `php artisan vendor:publish --tag=redactor-config`.

The file has two parts. The top of the file defines two pattern lists, `$credentialPatterns` and `$identityPatterns`, and the returned array spreads them into each profile. The returned array holds the global settings and the profiles.

Resolved profiles are cached and rebuilt only when the raw configuration behind them changes, so reading a profile on every redaction costs nothing measurable. Invalid values throw a `ConfigurationException` naming the offending path rather than falling back to a default silently.

## Top-Level Keys

### default_profile

| Type | Default | Environment variable |
| --- | --- | --- |
| `string` | `'default'` | `REDACTOR_DEFAULT_PROFILE` |

The profile used when none is named. It must be a key under `profiles`.

### scan

Settings for `redactor:scan`. None of them affect redaction of live payloads.

| Key | Type | Default | Env | Meaning |
| --- | --- | --- | --- | --- |
| `profile` | `string` | `'file_scan'` | `REDACTOR_SCAN_PROFILE` | The profile the scanner uses unless `--profile` is passed. |
| `exclude_patterns` | `string[]` | `*.lock`, `*.min.js`, `*.map`, `vendor/*`, `node_modules/*`, `storage/framework/*`, `public/build/*` | | Globs matched against each file's basename and its path relative to the scanned directory. A pattern ending in `/*` prunes that directory during the walk. |
| `max_file_size` | `int` | `10485760` | `REDACTOR_SCAN_MAX_FILE_SIZE` | Files larger than this many bytes are skipped. |
| `skip_binary` | `bool` | `true` | `REDACTOR_SCAN_SKIP_BINARY` | Skip files that contain a NUL byte or are mostly non-printable in their first 8 KB. |
| `respect_gitignore` | `bool` | `true` | `REDACTOR_SCAN_RESPECT_GITIGNORE` | Skip files git already ignores. |
| `window_lines` | `int` | `512` | `REDACTOR_SCAN_WINDOW_LINES` | How many lines are scanned at once. |
| `overlap_lines` | `int` | `4` | `REDACTOR_SCAN_OVERLAP_LINES` | How many lines each window shares with the previous one, so a secret spanning a boundary is still found. |
| `decode` | `bool` | `true` | `REDACTOR_SCAN_DECODE` | Look one layer deep inside base64, percent-encoded and JSON-escaped spans. |
| `verification.enabled` | `bool` | `false` | `REDACTOR_SCAN_VERIFY` | Allow `--verify` to contact providers. |
| `verification.verifiers` | `string[]` | `[]` | | The verifiers permitted to run: `github_token`, `stripe_key`, `slack_token`. An empty list means none. |
| `baseline` | `string\|null` | `base_path('.redactor-baseline.json')` | `REDACTOR_SCAN_BASELINE` | The file of accepted findings. |

See [Scanning](scanning.md) for what each of these does in practice.

### pseudonymization

Settings for the `hash`, `surrogate` and `tokenize` operators.

| Key | Type | Default | Env | Meaning |
| --- | --- | --- | --- | --- |
| `enabled` | `bool` | `true` | `REDACTOR_PSEUDONYMIZATION` | When false the pseudonymising operators fall back to plain redaction. |
| `key` | `string\|null` | `null` | `REDACTOR_PSEUDONYMIZATION_KEY` | The HMAC key. At least 16 bytes. Leave null to derive one from `APP_KEY`. |
| `salt` | `string\|null` | `null` | `REDACTOR_PSEUDONYMIZATION_SALT` | Mixed into every surrogate. Shared by every profile unless a profile sets its own. |

The mapping is one-way. Anyone holding the key can confirm a guess, so the key must not travel with the logs. Rotating it changes every surrogate. See [Operators and Pseudonymisation](operators-and-pseudonymisation.md#the-key-and-the-salt).

### tokenization

Settings for the `tokenize` operator and `Redactor::detokenize()`.

| Key | Type | Default | Env | Meaning |
| --- | --- | --- | --- | --- |
| `store` | `string\|null` | `null` | `REDACTOR_TOKEN_STORE` | The cache store that holds originals. Null means the default cache store. |
| `ttl` | `int\|null` | `86400` | `REDACTOR_TOKEN_TTL` | How many seconds a token can be exchanged back. Null keeps originals forever. |

Originals are encrypted with the application key before they reach the cache. See [Reversible Tokens](operators-and-pseudonymisation.md#reversible-tokens).

### events

| Type | Default | Environment variable |
| --- | --- | --- |
| `bool` | `true` | `REDACTOR_EVENTS` |

Whether to dispatch `RedactionPerformed` when a redaction changes something. See [Events](boundaries.md#events).

### profiles

An array of named profiles. Every key a profile accepts is described under [Profile Keys](#profile-keys).

### custom_strategies

| Type | Default |
| --- | --- |
| `array<string, class-string>` | `[]` |

Strategy classes registered under a short name, so a profile's `strategies` list can name them:

```php
'custom_strategies' => [
    'internal_data' => \App\Redaction\InternalDataStrategy::class,
],
```

Each class must implement `Kirschbaum\Redactor\Strategies\Contracts\Strategy`. See [Extending](extending.md#strategies).

## Profile Keys

Every profile accepts the keys below. Where the shipped `default` profile reads an environment variable, it is listed; the other profiles set literal values. The "Default" column is what applies when the key is absent from a profile, which is not always what the shipped profiles set.

### Strategies and Keys

| Key | Type | Default | Env | Meaning |
| --- | --- | --- | --- | --- |
| `enabled` | `bool` | `true` | `REDACTOR_ENABLED` | When false, `redact()` returns the content unchanged and `inspect()` reports nothing. |
| `strategies` | `string[]` | `[]` | | Strategy class names or `custom_strategies` names, in the order they run. |
| `safe_keys` | `string[]` | `[]` | | Keys whose values, subtrees included, are emitted untouched. Supports `*` wildcards, compared case-insensitively. |
| `blocked_keys` | `string[]` | `[]` | | Keys whose values are always redacted. Same wildcard syntax. |

### Rules

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `patterns` | `array<string, string\|array>` | `[]` | Named pattern rules, shorthand regex or full form. See [Rules](rules.md#pattern-rules). |
| `paths` | `array<string, string\|array>` | `[]` | Dotted path patterns mapped to an operator. See [Path Rules](rules.md#path-rules). |
| `allowlist` | `string[]` | `[]` | Literals and regexes that are never findings whichever detector reports them. See [Allow-Lists](rules.md#allow-lists). |
| `known_secrets` | `array` | `[]` | The application's own credentials. See [known_secrets](#known_secrets). |

### Operators and Confidence

| Key | Type | Default | Env | Meaning |
| --- | --- | --- | --- | --- |
| `operators` | `array<string, string\|array>` | `[]` | | What to do with each entity, plus a `default`. When absent the default operator is `redact`. See [Operators](operators-and-pseudonymisation.md). |
| `min_confidence` | `float` | `0.0` | `REDACTOR_MIN_CONFIDENCE` | Detections scoring below this are ignored. Must be between 0 and 1. See [Confidence](rules.md#confidence). |

### Output and Limits

| Key | Type | Default | Env | Meaning |
| --- | --- | --- | --- | --- |
| `replacement` | `string` | `'[REDACTED]'` | `REDACTOR_REPLACEMENT` | The text the `redact` operator writes. |
| `mark_redacted` | `bool` | `true` | `REDACTOR_MARK_REDACTED` | Add `'_redacted' => true` to an associative array that was changed. Never added to a list, never overwrites an existing `_redacted` key, never written into an HTTP response or MCP structured content. |
| `track_redacted_keys` | `bool` | `false` | `REDACTOR_TRACK_KEYS` | With `mark_redacted`, also add `_redacted_keys`. |
| `non_redactable_object_behavior` | `string` | `'preserve'` | `REDACTOR_OBJECT_BEHAVIOR` | What to do with an object that cannot be walked: `preserve`, `remove`, `redact` or `empty_array`. |
| `max_value_length` | `int\|null` | `null` | `REDACTOR_MAX_VALUE_LENGTH` | Strings longer than this many bytes are truncated or redacted. Null disables the check. |
| `large_string_behavior` | `string` | `'truncate'` | `REDACTOR_LARGE_STRING_BEHAVIOR` | `truncate` keeps the head, scans it and appends a note; `redact` replaces the whole value. |
| `redact_large_objects` | `bool` | `true` | `REDACTOR_LARGE_OBJECTS` | Whether `LargeObjectStrategy` does anything. |
| `max_object_size` | `int\|null` | `100` | `REDACTOR_MAX_OBJECT_SIZE` | Arrays and objects with more items than this are replaced with a summary. Null disables the check. |
| `max_depth` | `int` | `32` | `REDACTOR_MAX_DEPTH` | How many levels the walk descends before replacing the rest of the subtree. Guards cyclic and pathologically nested payloads. |

A truncated string looks like this:

```
<first 5000 bytes> [REDACTED] (String truncated: 65536 characters, 5000 kept)
```

The head is cut with `mb_strcut()` so it stays valid UTF-8, and the strategies after `LargeStringStrategy` still scan it.

### shannon_entropy

| Key | Type | Default | Env | Meaning |
| --- | --- | --- | --- | --- |
| `enabled` | `bool` | off when absent | `REDACTOR_SHANNON_ENABLED` | Whether the entropy detector runs. The strategy treats a missing key as disabled. |
| `threshold` | `float` | `4.8` | `REDACTOR_SHANNON_THRESHOLD` | Bits per character a token must reach, unless a charset threshold applies. |
| `min_length` | `int` | `25` | `REDACTOR_SHANNON_MIN_LENGTH` | Tokens shorter than this, in characters, are never measured. |
| `charset_thresholds` | `array<string, float>` | none | | Per-alphabet thresholds for `hex`, `base64` and `base64url`. When the token's alphabet has one, it wins over `threshold`. |
| `exclusion_patterns` | `string[]` | `[]` | | Regexes for tokens that score high without being sensitive: URLs, dates, UUIDs, IPs, MAC addresses, SQL. A pattern that cannot be evaluated excuses nothing. |

A hex digest cannot exceed 4.0 bits per character because it has 16 symbols, so judging it against 4.8 guarantees a miss. The shipped profiles set `hex` to 3.0 and both base64 alphabets to 4.5. The hex exclusion `/^[0-9a-f]+$/i` deliberately does not excuse strings of 32 characters or more, since those may be digests.

Tokens are whitespace-delimited. A value with no internal whitespace is one token, so a bare API key is reported whole; a sentence with a key in it reports only the key.

### recognition

Named entity recognition. Present in the shipped `default` profile and inert until enabled.

| Key | Type | Default | Env | Meaning |
| --- | --- | --- | --- | --- |
| `enabled` | `bool` | `false` | `REDACTOR_RECOGNITION` | Whether `EntityRecognitionStrategy` does anything. When false the strategy is left out of the chain entirely. |
| `driver` | `string` | `'presidio'` | | The registered recogniser to use. |
| `url` | `string` | `'http://127.0.0.1:5002/analyze'` | `REDACTOR_RECOGNITION_URL` | The Presidio `/analyze` endpoint. Only read by the `presidio` driver. |
| `language` | `string` | `'en'` | | Passed to the recogniser. |
| `entities` | `string[]` | `[]` (all) | | The recogniser's own labels to ask for. The shipped profile lists `PERSON`, `LOCATION`, `ORGANIZATION`, `NRP`. |
| `entity_map` | `array<string, string>` | `[]` | | Recogniser label to package entity, for `operators`. An unmapped label is lowercased. |
| `score_threshold` | `float` | `0.6` | | Spans scoring below this are dropped. |
| `min_length` | `int` | `20` | | Values shorter than this many bytes are not sent. |
| `max_length` | `int` | `5000` | | Values longer than this are not sent. |
| `min_words` | `int` | `3` | | Values with fewer whitespace-separated words are not sent. |
| `timeout` | `float` | `2.0` | | Seconds to wait for the recogniser. |
| `batch` | `bool` | `true` | | Send every prose value in a payload in one call before the walk, instead of one call per value. |
| `failure_threshold` | `int` | `3` | | Consecutive failures before the circuit breaker opens. |
| `cooldown` | `int` | `60` | | Seconds the breaker stays open. |

See [Entity Recognition](entity-recognition.md).

### known_secrets

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `values` | `string[]` | `[]` | Literal secrets. |
| `config` | `string[]` | `[]` | Config keys whose string values are secrets. A key that points at an array registers every string under it. |

The shipped profiles list `app.key`. Values shorter than 8 characters and nulls are skipped, so an unset secret in a local environment never fails the profile. See [Known Secrets](rules.md#known-secrets).

### pseudonymization (per profile)

A profile may carry its own `pseudonymization` block. Its non-null keys are merged over the global block, so a profile can set a `salt` of its own to stop its surrogates correlating with other profiles, or set `enabled` to false:

```php
'export' => [
    'pseudonymization' => ['salt' => 'export-2026'],
    // ...
],
```

## The Shared Pattern Lists

The two lists at the top of the config file are spread into the `default`, `strict`, `observability` and `file_scan` profiles. Order matters: on an equal confidence score the rule listed first wins an overlap, which is why `url_with_auth` sits ahead of `email` and `anthropic_key` ahead of `openai_key`.

`$credentialPatterns`, in order:

| Rule | Entity | Confidence | Notes |
| --- | --- | --- | --- |
| `url_with_auth` | `url_credentials` | 0.9 | Any scheme. Only the password is replaced (`capture` 2). |
| `private_key_block` | `private_key` | 1.0 | PEM `BEGIN ... PRIVATE KEY` to `END`, across lines. |
| `jwt` | `jwt` | 0.9 | Three base64url segments, the first two starting `eyJ`. |
| `bearer_token` | `bearer_token` | 0.85 | `Bearer <token>`; only the token is replaced. |
| `aws_access_key` | `aws_access_key` | 0.9 | `AKIA` or `ASIA` plus 16 characters. |
| `github_token` | `github_token` | 0.95 | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` and `github_pat_` tokens. |
| `stripe_key` | `stripe_key` | 0.95 | `sk_` and `rk_` keys only; publishable keys are meant to be seen. |
| `slack_token` | `slack_token` | 0.9 | `xox[abpors]-` tokens. |
| `anthropic_key` | `anthropic_key` | 0.95 | `sk-ant-` keys. |
| `openai_key` | `openai_key` | 0.9 | `sk-` and `sk-proj-` keys. |
| `google_api_key` | `google_api_key` | 0.9 | `AIza` plus 35 characters. |
| `sendgrid_key` | `sendgrid_key` | 0.95 | `SG.` keys. |

`$identityPatterns`, in order:

| Rule | Entity | Confidence | Notes |
| --- | --- | --- | --- |
| `email` | `email` | 0.8 | Byte-level, so non-ASCII local parts and domains match. Keyword `@`. |
| `phone_formatted` | `phone` | 0.6 | Needs separators or parentheses, so dates, versions and cards are not mistaken. |
| `phone_e164` | `phone` | 0.7 | `+` and 9 to 15 digits. |
| `phone_bare` | `phone` | 0.5 | Ten bare digits, only when the value contains `phone`, `tel`, `mobile`, `cell` or `fax`. |
| `ssn` | `ssn` | 0.7 | Hyphenated, with the `ssn` validator. |
| `ssn_bare` | `ssn` | 0.4 | Nine bare digits, only near `ssn`, `social security`, `tax id` or `tin`, with the validator. |
| `credit_card` | `credit_card` | 0.6 (default) | 13 to 16 digits with optional spaces or dashes, with the `luhn` validator. |
| `iban` | `iban` | 0.6 (default) | Compact or spaced, with the `iban` validator. |

Every rule in both lists declares `samples`, `counter_samples` and `min_length`, and every rule that can carries `keywords`. See [Rules](rules.md).

## The Shipped Profiles Compared

| Setting | `default` | `strict` | `observability` | `file_scan` | `performance` |
| --- | --- | --- | --- | --- | --- |
| Strategies | Safe, Blocked, LargeObject, LargeString, KnownSecrets, Regex, Entropy, Recognition | Safe, Blocked, LargeObject, LargeString, KnownSecrets, Regex, Entropy | Safe, Blocked, KnownSecrets, Regex, Entropy | KnownSecrets, Regex, Entropy | Safe, Blocked, KnownSecrets, Regex |
| Safe keys | 27 identifiers, timestamps and enumerations | 7 (`id`, `uuid`, `created_at`, `updated_at`, `timestamp`, `level`, `event`) | 21 | none | same 27 as `default` |
| Blocked keys | 24, including `*token*`, `*key*`, `*secret*`, `email`, names, `ssn`, card fields | `default` plus `secret`, `phone`, `address`, `user_agent`, `ip`, `name`, `username` | 8 (`password`, `*token*`, `*secret*`, `authorization`, `private_key`, `client_secret`, `cvv`, `pin`) | none | 7 (`password`, `secret`, `*token*`, `*key*`, `authorization`, `private_key`, `client_secret`) |
| Patterns | shared lists | shared lists, `ipv4`, `uuid` | shared lists, `ipv4` | shared lists, `api_key_generic`, `aws_secret_key`, `base64_key`, `password_assignment` | `email`, `simple_token` |
| Paths | none | none | `request.headers.authorization`, `request.headers.cookie`, `**.password` all `redact` | none | none |
| Operators | `credit_card` partial keep 4 | none configured (all `redact`) | `email` surrogate keeping domain, `phone` and `ip` surrogate, `credit_card` surrogate keeping 6-digit BIN | `credit_card` partial keep 4 | none configured |
| `min_confidence` | 0.0 | 0.0 | 0.4 | 0.0 | 0.0 |
| `mark_redacted` | true | true | false | true | false |
| `track_redacted_keys` | false | true | false | false | false |
| `non_redactable_object_behavior` | preserve | redact | preserve | preserve | preserve |
| `max_value_length` | 5000 | 1000 | 5000 | null | null |
| `redact_large_objects` | true | true | true | false | false |
| `max_object_size` | 100 | 25 | 100 | 100 | null |
| `max_depth` | 32 | 16 | 32 | 32 | 16 |
| Entropy | on, 4.8 over 25, charset thresholds | on, 4.0 over 15, no charset thresholds | on, 4.8 over 25, charset thresholds | on, 4.8 over 25, charset thresholds, extra word and number exclusions | off |
| Known secrets | `app.key` | `app.key` | `app.key` | `app.key` | `app.key` |
| Recognition | present, disabled | not listed | not listed | not listed | not listed |

## Environment Variables

Every variable the shipped configuration reads:

```env
# Global
REDACTOR_DEFAULT_PROFILE=default
REDACTOR_EVENTS=true

# Pseudonymisation and tokens
REDACTOR_PSEUDONYMIZATION=true
REDACTOR_PSEUDONYMIZATION_KEY=
REDACTOR_PSEUDONYMIZATION_SALT=
REDACTOR_TOKEN_STORE=
REDACTOR_TOKEN_TTL=86400

# The default profile
REDACTOR_ENABLED=true
REDACTOR_REPLACEMENT="[REDACTED]"
REDACTOR_MARK_REDACTED=true
REDACTOR_TRACK_KEYS=false
REDACTOR_OBJECT_BEHAVIOR=preserve
REDACTOR_MAX_VALUE_LENGTH=5000
REDACTOR_LARGE_STRING_BEHAVIOR=truncate
REDACTOR_LARGE_OBJECTS=true
REDACTOR_MAX_OBJECT_SIZE=100
REDACTOR_MAX_DEPTH=32
REDACTOR_MIN_CONFIDENCE=0.0
REDACTOR_SHANNON_ENABLED=true
REDACTOR_SHANNON_THRESHOLD=4.8
REDACTOR_SHANNON_MIN_LENGTH=25
REDACTOR_RECOGNITION=false
REDACTOR_RECOGNITION_URL=http://127.0.0.1:5002/analyze

# Scanning
REDACTOR_SCAN_PROFILE=file_scan
REDACTOR_SCAN_MAX_FILE_SIZE=10485760
REDACTOR_SCAN_SKIP_BINARY=true
REDACTOR_SCAN_RESPECT_GITIGNORE=true
REDACTOR_SCAN_WINDOW_LINES=512
REDACTOR_SCAN_OVERLAP_LINES=4
REDACTOR_SCAN_DECODE=true
REDACTOR_SCAN_VERIFY=false
REDACTOR_SCAN_BASELINE=.redactor-baseline.json
```

Only the `default` profile reads the per-profile variables. The other shipped profiles set literal values, so `REDACTOR_MAX_VALUE_LENGTH` changes `default` and nothing else.

## How Values Are Validated

`env()` hands every value over as a string, so each key is coerced and checked when the profile is built:

- Booleans accept `true`, `false`, `1`, `0`, and the strings `true`, `false`, `1`, `0`, `yes`, `no`, `on`, `off` and an empty string, case-insensitively.
- Integers must be positive; `max_value_length` and `max_object_size` also accept null, and an empty string from `env()` counts as null.
- `non_redactable_object_behavior`, `large_string_behavior` and a rule's `mode` and `validator` must be one of the documented values.
- `min_confidence` must be between 0 and 1.
- A pattern that does not compile is dropped from the profile; a rule with no `pattern` and no `words`, or with a bad `mode`, throws.

Anything that fails throws a `ConfigurationException` whose message names the path, such as `profiles.default.max_depth`. `php artisan redactor:validate` surfaces all of them at once.

## Region Packs

`regions` at the top level holds pattern lists grouped by country: `gb`, `nl`,
`de`, `fr`, `it`, `es`, `be`, `se`, `no`, `ca`, `au` and `eu`. A profile's
`regions` key lists the packs to spread into its patterns. Packs are off unless
listed. See [Region Packs](rules.md#region-packs).

