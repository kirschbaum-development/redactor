# Rules

- [Introduction](#introduction)
- [Pattern Rules](#pattern-rules)
    - [Shorthand and Full Form](#shorthand-and-full-form)
    - [Modes](#modes)
    - [Capture Groups](#capture-groups)
    - [Validators](#validators)
    - [Keywords](#keywords)
    - [Minimum Length](#minimum-length)
    - [Samples](#samples)
    - [Dictionary Rules](#dictionary-rules)
    - [Per-Rule Allow Lists](#per-rule-allow-lists)
    - [Entity and Operator](#entity-and-operator)
- [Allow-Lists](#allow-lists)
- [Path Rules](#path-rules)
- [Safe and Blocked Keys](#safe-and-blocked-keys)
    - [Wildcards](#wildcards)
- [Known Secrets](#known-secrets)
- [Confidence](#confidence)
- [How Detections Are Resolved](#how-detections-are-resolved)
- [PCRE Failures](#pcre-failures)

## Introduction

A rule is anything that tells the redactor a value is sensitive. There are four kinds, and they answer different questions:

| Kind | Asks | Configured under |
| --- | --- | --- |
| Pattern rule | Does the value look like a secret? | `patterns` |
| Path rule | Is the value at this exact location? | `paths` |
| Key rule | Is the value under a key with this name? | `safe_keys`, `blocked_keys` |
| Known secret | Is one of the application's own credentials in the value? | `known_secrets` |

A rule only detects. What replaces a detected value is decided by an [operator](operators-and-pseudonymisation.md).

## Pattern Rules

### Shorthand and Full Form

A pattern is a named entry under `patterns`. The shorthand is a bare regex, and the matched span is replaced with the profile's replacement string:

```php
'patterns' => [
    'internal_id' => '/\bINT-\d{8}\b/',
],
```

The full form is an array with a `pattern` and any of the options below:

```php
'patterns' => [
    'credit_card' => [
        'pattern'        => '/\b(?:\d[ -]*?){13,16}\b/',
        'mode'           => 'partial',
        'keep'           => 4,
        'mask_character' => '*',
        'validator'      => 'luhn',
        'entity'         => 'credit_card',
        'confidence'     => 0.6,
        'keywords'       => [],
        'min_length'     => 13,
        'samples'        => ['4111111111111111'],
        'counter_samples' => ['1234567890123456'],
        'allow'          => [],
    ],
],
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `pattern` | `string` | required unless `words` is given | The regex, with delimiters. |
| `words` | `string[]` | | A dictionary instead of a regex. See [Dictionary Rules](#dictionary-rules). |
| `mode` | `string` | `replace` | How to rewrite the match. See [Modes](#modes). |
| `keep` | `int` | `4` | Characters kept by `partial` mode. |
| `mask_character` | `string` | `*` | The character `mask` and `partial` write. Only the first character is used. |
| `capture` | `int` | `0` | The capture group holding the secret. See [Capture Groups](#capture-groups). |
| `validator` | `string` | none | `luhn`, `iban` or `ssn`. See [Validators](#validators). |
| `entity` | `string` | the rule name | What kind of thing the rule finds, for `operators`. |
| `confidence` | `float` | `0.6` | The base score of a bare match. See [Confidence](#confidence). |
| `operator` | `string\|array` | none | An operator the rule chooses for itself. See [Entity and Operator](#entity-and-operator). |
| `keywords` | `string[]` | `[]` | Literals at least one of which must appear in the value. See [Keywords](#keywords). |
| `min_length` | `int` | `1` | The shortest text the pattern can match, in bytes. See [Minimum Length](#minimum-length). |
| `samples` | `string[]` | `[]` | Texts the rule must detect. See [Samples](#samples). |
| `counter_samples` | `string[]` | `[]` | Texts the rule must not detect. |
| `allow` | `string[]` | `[]` | Matches this rule alone should let through. See [Per-Rule Allow Lists](#per-rule-allow-lists). |

A pattern that does not compile is silently dropped from the profile rather than throwing; `redactor:validate` will then report the rule's samples as undetected, if it has any. A rule with no `pattern` and no `words`, or an unrecognised `mode` or `validator`, is a configuration error and throws.

### Modes

`mode` says how the matched span is rewritten:

| Mode | Result for `4111111111111111` |
| --- | --- |
| `replace` (default) | `[REDACTED]` |
| `mask` | `****************`, length preserved |
| `partial` | `************1111`, the last `keep` characters kept |
| `remove` | deleted |
| `full` | the entire value is replaced, not just the match |

Character counts are multibyte-aware. A `partial` match no longer than `keep` is masked entirely, since revealing any of it would reveal all of it.

`mask`, `partial` and `remove` are translated into the operators of the same name. `full` is the pre-1.0 behaviour and condemns the whole value on one match; prefer a blocked key or a path rule where that is what you mean.

### Capture Groups

Some patterns need surrounding context to match confidently, but the context is not itself sensitive. Name the group holding the secret and the rest survives:

```php
'aws_secret_key' => [
    'pattern' => '/(aws_secret_access_key\s*=\s*)([A-Za-z0-9\/+]{40})/i',
    'capture' => 2,
],

// aws_secret_access_key = [REDACTED]
```

If the named group did not participate in the match, the whole match is used instead. The shipped `url_with_auth` and `bearer_token` rules work this way, so the host of a credential URL and the word `Bearer` stay readable.

### Validators

A regex asserts shape only. `/\b(?:\d[ -]*?){13,16}\b/` matches order numbers and concatenated timestamps as readily as cards. A validator asserts that the value could be what the pattern claims, and a match that fails one is left alone:

| Validator | Check |
| --- | --- |
| `luhn` | The payment card check digit, on 12 to 19 digits. |
| `iban` | ISO 13616 mod-97, on 15 to 34 characters. |
| `ssn` | US allocation rules: area not 000, 666 or 900 and above; group not 00; serial not 0000. |

```php
Redactor::redact('order 2024010112000001 shipped'); // untouched: fails Luhn
Redactor::redact('paid with 4111111111111111');     // 'paid with ************1111'
```

A passing validator also raises the match's confidence. See [Confidence](#confidence).

### Keywords

A rule can name literals at least one of which must appear somewhere in the value, compared case-insensitively, before the pattern is tried:

```php
'email' => ['pattern' => '/[^@\s]+@[^@\s]+/', 'keywords' => ['@']],

'phone_bare' => [
    'pattern'  => '/(?<!\d)\d{10}(?!\d)/',
    'keywords' => ['phone', 'tel', 'mobile', 'cell', 'fax'],
],
```

Keywords do two jobs. The first is cost: "does this value contain an `@`" is one `str_contains()`, so almost every string in a log payload skips the email regex. The second is precision: a bare ten-digit run is a phone number in a value that says `phone` and a Unix timestamp almost everywhere else.

The keyword must be in the value, not the key. A rule that should fire because of the key name is a [blocked key](#safe-and-blocked-keys).

### Minimum Length

A rule can state the shortest text it could possibly match, in bytes:

```php
'aws_access_key' => ['pattern' => '/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/', 'min_length' => 20],
```

A shorter value skips the rule with one integer compare. Rules are sorted by `min_length` when the profile is built, so once the subject is shorter than a rule's minimum every rule after it is skipped too. Sorting changes only the order rules are *tried*; declared order still decides an equal-score overlap.

The number must never exceed the true minimum or the rule misses real matches. When in doubt leave it out. Every shipped rule declares one.

### Samples

A rule can carry the texts it exists to catch, and texts it must leave alone:

```php
'order_ref' => [
    'pattern'         => '/\bORD-\d{6}\b/',
    'samples'         => ['ref ORD-123456'],
    'counter_samples' => ['ORD-12', 'ORDER-123456'],
],
```

`php artisan redactor:validate` runs every sample through the real detection path, with keywords, minimum length, validator and allow lists applied, and fails when a rule no longer detects a sample or detects a counter-sample. A regex edit that quietly stops matching what it was written for then fails CI instead of an audit. Every shipped rule carries both.

### Dictionary Rules

A rule can be a list of words instead of a regex. Product codenames, internal project names, a customer list: things no pattern can express and no model would know.

```php
'codenames' => ['words' => ['Project Falcon', 'Orion'], 'entity' => 'codename'],
```

The words are compiled into one whole-word, case-insensitive alternation, longest first, so `Project Falcon` is one finding rather than two and `Orionids` is left alone. Every other rule option applies. An empty list throws.

### Per-Rule Allow Lists

A rule can carry exceptions scoped to that rule alone:

```php
'email' => ['pattern' => '/[^@\s]+@[^@\s]+/', 'allow' => ['/@example\.com$/']],
```

Entries follow the same rules as the profile [allow-list](#allow-lists): a literal compared case-insensitively, or a regex when the entry is delimited like one. A rejected match is simply not a detection, so another rule can still report the same span.

### Entity and Operator

`entity` names what kind of thing the rule finds. It defaults to the rule name and is what `operators` keys on, so three phone rules sharing `'entity' => 'phone'` are governed by one `operators.phone` entry.

A rule can also choose its own operator:

```php
'card' => [
    'pattern'  => '/\b\d{16}\b/',
    'operator' => ['partial' => ['keep' => 4]],
],
```

Only a rule that explicitly sets `operator` or a non-default `mode` outranks the profile's `operators.default`. A rule with no preference defers to it. See [Precedence](operators-and-pseudonymisation.md#precedence).

## Allow-Lists

Some values look sensitive and are known not to be: the support address on every page, the sandbox card in every fixture, the example key in the docs. List them rather than weakening the pattern that finds them:

```php
'allowlist' => [
    'noreply@example.com',        // a literal, trimmed and compared case-insensitively
    '/^test-\d+@example\.com$/',  // a regex, recognised by its delimiters
],
```

The allow-list is checked after detection, whichever detector reported the value: a pattern, entropy, a known secret, a blocked key or a path rule. The rules stay as strong as they were written and an allowed value is simply not a finding. A regex entry that cannot be evaluated allows nothing, since the failure mode of an allow-list is a leak.

An entry is treated as a regex when its first character is not alphanumeric, a backslash or whitespace, and the matching closing delimiter appears at the end, optionally followed by modifiers. Anything else is a literal.

## Path Rules

A path says exactly where a value lives. Every other rule infers that from a key name or from the content.

```php
'paths' => [
    'request.headers.authorization' => 'redact',
    'user.*.email'                  => 'surrogate',
    '**.password'                   => 'redact',
    'users[*].token'                => 'redact',
    'debug'                         => 'preserve',
],
```

| Segment | Matches |
| --- | --- |
| `literal` | That key exactly, case-insensitively. |
| `*` | Any single level. |
| `**` | Any depth, including none. |
| `[*]` | A list index. `users[*].x` and `users.*.x` are the same pattern. |
| `[0]` | A specific index. `items[0]` and `items.0` are the same. |

Each value is an operator, in any of the [three spellings](operators-and-pseudonymisation.md#configuring-operators).

Paths are checked before anything else and, when one matches, *instead of* everything else: no key matching, no pattern scanning, no walk below the matched node. The more specific pattern always wins, scored by segment (a literal counts 3, `*` counts 2, `**` counts 1), so declaration order never matters, and `preserve` carves an exception out of a broader rule without disabling it.

A path rule on a scalar gets the full operator range and is reported with a certain confidence and the rule name `path:<pattern>`; the key is its entity. A path rule on an array or object supports `preserve`, `remove` and `nullify`; any other operator collapses the subtree to the replacement string, since masking or pseudonymising an array has no defensible meaning. The profile allow-list still applies to scalars.

Paths compile once into a trie walked in lockstep with the payload, so the cost tracks the rules currently in play rather than the number configured. Two hundred path rules cost about the same as one.

## Safe and Blocked Keys

`blocked_keys` lists keys whose values are always redacted. `safe_keys` lists keys whose values are always preserved. Both are compared case-insensitively.

```php
'safe_keys'    => ['id', 'user_id', 'created_at', '*_count'],
'blocked_keys' => ['password', '*token*', '*key*', 'user_*_data'],
```

Two things about `safe_keys` matter more than they look:

- A safe key preserves the **entire subtree**. `SafeKeysStrategy` ends the chain and stops the walk, so everything nested under a safe key is emitted untouched. Only list keys whose contents cannot carry sensitive data by construction: identifiers, timestamps, enumerations. A free-text field like `message` is not safe because it usually looks harmless.
- `SafeKeysStrategy` runs first in the shipped profiles, so a key listed in both lists is never redacted. `redactor:validate` reports the conflict.

A value under a blocked key is reported with a certain confidence, the rule name `blocked_key`, and the lowercased key as its entity. That is what lets `operators.email` apply to `['email' => ...]` and to an address inside a message alike. A blocked key holding an array, boolean or null collapses to the replacement string, since there is no text for an operator to act on; `nullify` keeps the key and writes null.

### Wildcards

Both lists accept `*`:

| Pattern | Matches |
| --- | --- |
| `password` | `password` exactly |
| `*token*` | any key containing `token`: `api_token`, `token_data`, `MyTokenField` |
| `password*` | any key starting with `password`: `password_hash`, `password_confirmation` |
| `*_key` | any key ending with `_key`: `private_key`, `api_key` |
| `user_*_token` | `user_api_token`, `user_auth_token` |
| `*` | every key |

Lists are compiled once, and each pattern becomes the cheapest test for its shape: a hash lookup for exact names, `str_contains()` for `*word*`, `str_starts_with()` and `str_ends_with()` for one-sided wildcards. Only a pattern with an interior wildcard such as `user_*_token` reaches PCRE, compiled once. The shape of your list barely matters in practice.

## Known Secrets

Every other detector infers. This one knows: the application's own credentials are already in config, and a log line containing one of them verbatim is a leak whatever it looks like.

```php
'known_secrets' => [
    'values' => [env('LEGACY_SIGNING_KEY')],
    'config' => [
        'app.key',                              // shipped default
        'services.stripe.secret',
        'database.connections.mysql.password',
        'services.acme',                        // an array: every string under it
    ],
],
```

Matching is exact and case-sensitive. Values under 8 characters and nulls are skipped, so an unset secret in a local environment never fails the profile. A registered value is reported with a certain confidence, the rule name `known_secret` and the entity `known_secret`.

A credential that only exists at runtime is registered the same way, for every profile:

```php
Redactor::registerSecret($vault->read('signing-key'));
Redactor::registerSecret($token, entity: 'vault_token');
```

`registerSecret()` returns false if the value was too short to register.

## Confidence

Binary matching forces a choice between noise and misses: the only way to quieten a rule is to weaken its regex everywhere. Detections carry a score instead.

```php
'patterns' => [
    'card' => ['pattern' => '/\b\d{16}\b/', 'confidence' => 0.3, 'validator' => 'luhn'],
],

'min_confidence' => 0.5,
```

The base score comes from the rule. Two signals raise it:

| Signal | Delta | When |
| --- | --- | --- |
| `validator` | +0.75 | The rule has a validator and the match passed it. |
| `context` | +0.25 | A credential keyword (`secret`, `token`, `password`, `apikey`, `bearer`, `key`, `card`, `cvv`, `ssn` and others) appears in the 40 bytes before the match, or in the key the value sits under. |

Deltas apply to the remaining headroom rather than adding flat, so signals stack toward 1.0 without exceeding it: 0.3 with a validator becomes 0.825, and with a keyword too 0.87. The same pattern is therefore filtered out as noise on its own and reported when something corroborates it, without editing the pattern.

Entropy detections start at 0.5, climb by up to 0.4 as the token's entropy clears its threshold, and gain the same context boost. Values found by a blocked key, a path rule or a known secret are certain (1.0). Recognised entities start at the recogniser's own score. `min_confidence` applies to all of them.

Every finding explains itself. `inspect()` and `redactor:scan` report the score and the signals behind it:

```json
{
  "rule": "card",
  "confidence": 0.87,
  "signals": [
    "base +0.30 (pattern \"card\" matched)",
    "validator +0.75 (luhn checksum passed)",
    "context +0.25 (a credential keyword appears alongside the match)"
  ]
}
```

Scores map to labels at 0.9 (high), 0.6 (medium) and 0.3 (low); anything lower is very low.

## How Detections Are Resolved

The regex, entropy, known-secret and recognition strategies are *detectors*. They report what they found and where, and change nothing. Once every detector in the chain has seen a value, the context resolves the reports and rewrites the original string in one pass:

1. Detections below `min_confidence` are dropped.
2. Where two detections overlap, the higher score wins. On an equal score the rule declared first in `patterns` wins, then the report that arrived first.
3. Detections whose value is on the allow-list are dropped.
4. Each surviving span is handed to its operator and written into the output left to right.

Three things follow:

- An API key beside an email address is not spared because the email matched first. Both are reported, both are rewritten.
- A surrogate written for one detection is never re-detected by the next detector. It has the same shape and entropy as the value it replaced, and a sequential chain would have redacted it again.
- Every finding's offset is a byte offset into the value you passed, so the scanner reports the right column for the second secret on a line.

Length is deliberately not a criterion in step 2, since it would let a greedy general rule swallow the precise one beside it. A Luhn-validated card (0.6 + 0.75) outranks the bare digit run that also matched it, and `url_with_auth` declared ahead of `email` takes the password out of `https://user:pass@host` and leaves the host.

A `preserve` operator reports the finding through `inspect()` without marking the payload redacted, which is what a scan that should only report wants.

## PCRE Failures

Every regex is evaluated fail-closed. If PCRE gives up on a pattern, because of the backtrack limit, the JIT stack limit or invalid UTF-8, the value is treated as sensitive rather than clean: the whole value is replaced, the failure is logged with the rule name, and the finding is reported with a certain confidence.

The exceptions are the places where a failure would otherwise excuse a value. An allow-list entry, an entropy exclusion pattern or a safe-key pattern that cannot be evaluated allows nothing. A blocked-key pattern that cannot be evaluated blocks the key.

## Region Packs

National identifiers and VAT numbers are grouped by country under `regions`
in `config/redactor.php` and switched on per profile:

```php
'profiles' => [
    'default' => [
        'regions' => ['gb', 'nl', 'eu'],
    ],
],
```

| Pack | Rules | Checks |
| --- | --- | --- |
| `gb` | National Insurance number, NHS number, VAT | NHS mod-11, VAT mod-97 |
| `nl` | BSN, VAT | eleven-proof, weighted mod-11 |
| `de` | Steuer-ID, VAT | ISO 7064 mod 11,10 |
| `fr` | NIR, VAT | mod-97 key, SIREN key |
| `it` | codice fiscale, VAT | check character, Luhn |
| `es` | DNI and NIE, VAT | mod-23 letter |
| `be` | national register number, VAT | mod-97, both centuries |
| `se` | personnummer, VAT | date plausibility and Luhn |
| `no` | fødselsnummer | two mod-11 control digits |
| `ca` | SIN | Luhn |
| `au` | TFN | weighted mod-11 |
| `eu` | VAT for the remaining member states | format |

Identifiers whose shape is too common on its own, a nine-digit BSN or SIN, a
ten-digit NHS number, also require a label such as `bsn`, `sin` or `nhs`
somewhere in the value, so an order number is not mistaken for one. Every
pack rule carries samples and counter-samples that `redactor:validate` proves,
and a rule in the profile's own `patterns` with the same name wins over the
pack's.

Region rules use the entities `national_id`, `health_id` and `vat_number`, so
one operator covers a whole class:

```php
'operators' => ['national_id' => 'hash', 'vat_number' => 'preserve'],
```

## Custom Validators

Register a validator of your own and name it from any rule:

```php
use Kirschbaum\Redactor\Patterns\Validator;

Validator::extend('policy_number', fn (string $value): bool => PolicyNumber::isValid($value));
```

```php
'policy' => ['pattern' => '/\bPOL-\d{8}\b/', 'validator' => 'policy_number'],
```

A rule naming a validator that does not exist is a configuration error, so a
typo fails `redactor:validate` rather than silently disabling the check.

