# Kirschbaum Redactor

![Laravel Supported Versions](https://img.shields.io/badge/laravel-12.x%20%7C%2013.x-green.svg)
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

If you need to know whether anything matched, inspect rather than reading it
back out of the payload:

```php
$result = Redactor::inspect($data);

$result->value;         // the redacted payload
$result->wasRedacted;   // bool
$result->redactedKeys;  // ['password', 'api_key', 'email']
$result->findings;      // rule, entity, offset, length and score for each match
$result->toArray();     // the same, without the matched text; also JsonSerializable
```

A profile and its options read fluently:

```php
Redactor::profile('strict')->redact($data);
Redactor::profile('observability')->withoutMarkers()->inspect($data);
Redactor::profile('audit')->when($verbose, fn ($r) => $r->withMarkers())->redact($data);
```

Everything the package throws implements `Exceptions\RedactorException`; a
missing profile is a `ProfileNotFoundException`, a bad value a
`ConfigurationException`, both still `InvalidArgumentException`s.

## Core Concepts

### Redaction Strategies

The package uses a class-based configuration:

1. **SafeKeysStrategy** - Preserves safe keys like `id`, `user_id`
2. **BlockedKeysStrategy** - Always redacts blocked keys like `password`, `secret`
3. **LargeObjectStrategy** - Redacts objects/arrays exceeding size limits
4. **LargeStringStrategy** - Truncates strings exceeding length limits, scanning the head it keeps
5. **KnownSecretsStrategy** - Redacts the application's own credentials wherever they appear verbatim
6. **RegexPatternsStrategy** - Custom regex patterns for emails, credit cards, etc.
7. **ShannonEntropyStrategy** - Detects high-entropy strings (API keys, tokens)
8. **EntityRecognitionStrategy** - Asks a named entity recogniser about free text; inert until enabled

Strategies run in the order the profile lists them, and the chain stops at the
first strategy that replaces a value outright. The regex and entropy strategies
are *detectors*: they report what they found and where, and change nothing.
Once every detector has seen the value, the context resolves their reports and
rewrites the original string once. Three things follow from that:

- An API key sitting next to an email address is not spared because the email
  matched first - both are reported, both are rewritten.
- A surrogate written for one detection is never re-detected by the next
  detector. It has the same shape and entropy as the value it replaced, and a
  sequential chain would have redacted it again.
- Every finding's offset is an offset into the value you passed, so the scanner
  reports the right column for the second secret on a line.

Where two detections overlap, the higher score wins - a Luhn-validated card
outranks the bare digit run that also matched it. On an equal score the rule
listed first wins, so `url_with_auth` declared ahead of `email` takes the
password out of `https://user:pass@host` and leaves the host.

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
                // The shipped config defines two lists at the top of the file
                // and spreads them into every profile, so the profiles cannot
                // drift apart. $credentialPatterns: credential URLs, PEM
                // blocks, JWTs, bearer tokens, and AWS, GitHub, Stripe, Slack,
                // OpenAI, Anthropic, Google and SendGrid keys.
                // $identityPatterns: emails, phones, SSNs, cards and IBANs.
                ...$credentialPatterns,
                ...$identityPatterns,

                // Shorthand: matched span replaced with the replacement string
                'internal_id' => '/\bINT-\d{8}\b/',

                // Full rule form - see "Pattern Rules" below
                'credit_card' => [
                    'pattern' => '/\b(?:\d[ -]*?){13,16}\b/',
                    'validator' => 'luhn',    // reject non-cards of the same shape
                    'entity' => 'credit_card',
                    'keywords' => [],         // literals that must be present first
                ],
            ],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve', // 'preserve', 'remove', 'redact', 'empty_array'
            'max_value_length' => 5000,
            'large_string_behavior' => 'truncate', // keep the head and scan it; 'redact' replaces the value
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

### Keywords

A rule can name literals at least one of which must appear somewhere in the
value before the pattern is tried, compared case-insensitively:

```php
'email' => ['pattern' => '/[^@\s]+@[^@\s]+/', 'keywords' => ['@']],

'phone_bare' => [
    'pattern'  => '/\b\d{10}\b/',
    'keywords' => ['phone', 'tel', 'mobile', 'cell', 'fax'],
],
```

It does two jobs. The first is cost: the email pattern is the single most
expensive thing in a scan of clean text, and "does this value contain an @"
answers it for the price of one `str_contains()`, so almost every string in a
log payload skips it. The second is precision: a bare ten-digit run is a phone
number in a value that says `phone` and a Unix timestamp almost everywhere
else, and a keyword lets the rule ask for the label without a regex that has to
know where the label sits.

### Minimum length

A rule can also state the shortest text it could possibly match:

```php
'aws_access_key' => ['pattern' => '/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/', 'min_length' => 20],
```

A shorter value skips the rule with one integer compare, before PCRE is
involved. Most values in a log payload are a few bytes and most credential
rules need twenty or more, so this retires most of the list on most values.
The number must never exceed the true minimum or the rule misses real
matches; when in doubt leave it out. Every shipped rule declares one.

### Samples

A rule can carry the texts it exists to catch, and texts it must leave alone:

```php
'order_ref' => [
    'pattern'         => '/\bORD-\d{6}\b/',
    'samples'         => ['ref ORD-123456'],
    'counter_samples' => ['ORD-12', 'ORDER-123456'],
],
```

`redactor:validate` runs every sample through the real detection path, with
the rule's keywords, minimum length, validator and allow-list applied, and
fails the deploy when a rule no longer detects a sample or detects a
counter-sample. A regex edit that quietly stops matching the thing it was
written for then fails CI instead of an audit. Every shipped rule carries
both.

### Dictionary rules

A rule can be a list of words instead of a regex. Product codenames, internal
project names, a customer list: things no pattern can express and no model
would know.

```php
'codenames' => ['words' => ['Project Falcon', 'Orion'], 'entity' => 'codename'],
```

Words are matched whole and case-insensitively, longest first, so `Project
Falcon` is one finding rather than two and `Orionids` is left alone.

### Allow-lists

Some values look sensitive and are known not to be: the support address on
every page, the sandbox card in every fixture, the example key in the docs.
List them rather than weakening the pattern that finds them:

```php
'allowlist' => [
    'noreply@example.com',          // a literal, compared case-insensitively
    '/^test-\d+@example\.com$/',    // or a regex
],
```

The allow-list is checked after detection, whichever detector reported the
value - a pattern, entropy, a blocked key or a path rule - so the rules stay as
strong as they were written and an allowed value is simply not a finding. A
regex entry that cannot be evaluated allows nothing.

A rule can carry its own exceptions, scoped to that rule alone:

```php
'email' => ['pattern' => EMAIL, 'allow' => ['/@example\.com$/']],
```

## Known Secrets

Every other detector infers. This one knows: the application's own credentials
are already in config, and a log line containing one of them verbatim is a leak
whatever it looks like.

```php
'known_secrets' => [
    'values' => [env('LEGACY_SIGNING_KEY')],
    'config' => [
        'app.key',                                // shipped default
        'services.stripe.secret',
        'database.connections.mysql.password',
        'services.acme',                          // an array: every string under it
    ],
],
```

Matching is exact and case-sensitive. Values under eight characters and nulls
are skipped, so an unset secret in a local environment never fails the profile.
A credential that only exists at runtime is registered the same way:

```php
Redactor::registerSecret($vault->read('signing-key'));
```

## Entity Recognition

Names, addresses and organisations are the PII no regex can express and no
entropy measure can see. A named entity recogniser can find them, at a cost
three orders of magnitude above the rule engine, so the package treats it as
a gated extra rather than a default.

The recogniser speaks Presidio's `/analyze` contract - text in, a list of
`{entity_type, start, end, score}` out - so the reference Presidio analyzer,
the same analyzer with a transformer recogniser, or a small wrapper around any
fine-tuned model all work without a line of PHP:

```php
'recognition' => [
    'enabled'         => true,
    'driver'          => 'presidio',
    'url'             => 'http://presidio:5002/analyze',
    'entities'        => ['PERSON', 'LOCATION', 'ORGANIZATION'],
    'entity_map'      => ['PERSON' => 'person', 'LOCATION' => 'location'],
    'score_threshold' => 0.6,
],

'operators' => [
    'person'   => 'surrogate',
    'location' => 'redact',
],
```

What the gate does:

- Only values that read as prose, between `min_length` and `max_length`, are
  sent. A JSON blob, a stack trace or a bare token is not something a model
  reads well, and its guesses would be the false positives the gate exists to
  prevent.
- Only the labels listed, at or above `score_threshold`, become findings.
- Every span comes back in character offsets and is converted to bytes and
  checked against the value before it is replaced. A span that does not line
  up is skipped, never guessed.
- A recogniser that fails is skipped and the output is rules-only. After
  `failure_threshold` consecutive failures it is not asked again for
  `cooldown` seconds, so a dead sidecar costs one timeout, not one per log
  line.
- Recognised spans go through the same overlap resolution, confidence floor
  and operators as everything else. A `person` becomes a stable surrogate
  exactly the way an email does.

Enable it on the profiles used from queues, exports and scans, not on the
request path. To plug in something that does not speak the Presidio contract,
implement `Recognition\Recognizer` and register it:

```php
Redactor::registerRecognizer(new MyOnnxRecognizer);   // then 'driver' => 'my-onnx'
```

## Path Rules

A path says exactly where a value lives. Every other rule in this package is
inferring that from a key name or from the contents.

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
| `literal` | that key exactly, case-insensitively |
| `*` | any single level |
| `**` | any depth, including none |
| `[*]` | a list index; `users[*].x` and `users.*.x` are the same |

Paths are checked first and, when one matches, *instead of* everything else — no
key matching, no pattern scanning, no walk below the matched node. The more
specific pattern always wins, so declaration order never matters, and `preserve`
carves an exception out of a broader rule without disabling it.

They compile once into a trie that is walked in lockstep with the payload, so
the cost tracks the rules currently in play rather than the number configured.
Two hundred path rules cost about the same as one.

## Operators

Detection asks "is this sensitive". An operator answers "so what". They are
separate because the right answer differs by context for the very same value.

```php
'operators' => [
    'default'     => 'redact',
    'email'       => ['surrogate' => ['preserve_domain' => true]],
    'credit_card' => ['partial' => ['keep' => 4]],
],
```

| Operator | Result |
| --- | --- |
| `redact` | `[REDACTED]` |
| `mask` | `****************` — length preserved |
| `partial` | `************1111` — last N kept |
| `remove` | deleted |
| `hash` | `[email:k4m9rp2xzq]` — stable, obviously not real |
| `surrogate` | `u_7f3ac9@customer.com` — stable, same shape |
| `nullify` | `null` — the key stays, a typed field stays typed |
| `preserve` | detected and reported, unchanged |

Precedence runs most specific first: the path it was found at, then the entity
it is, then the rule that found it, then the profile default. Entity beats rule
deliberately — "every email here becomes a surrogate" is a policy decision about
data, and which regex spotted it is an implementation detail.

Every detector goes through the same policy. A value found by its key uses the
key name as its entity, so `operators.email` applies to `['email' => ...]` and
to an address inside a message alike, and both produce the same surrogate. A
high-entropy token has the entity `high_entropy`. A `preserve` operator reports
the finding through `inspect()` without marking the payload redacted,
which is what a scan that should only report wants.

Register your own with `Redactor::registerOperator('tokenize', $operator)` and
use it from config by name.

## Pseudonymisation

Replacing every value with `[REDACTED]` collapses distinct values into one,
which destroys the questions logs exist to answer: how many users hit this, is
it always the same account, did this session span both services.

`surrogate` and `hash` replace a value with a *stable* stand-in instead. The
same input always produces the same output, so counts, joins and traces survive:

```php
Redactor::redact('login by alice@customer.com', 'observability');
// 'login by u_7f3ac9@customer.com'

Redactor::redact('logout for alice@customer.com', 'observability');
// 'logout for u_7f3ac9@customer.com'   <- same surrogate, still joinable
```

Surrogates preserve shape, so anything downstream that parses the value keeps
parsing it:

| Original | Surrogate |
| --- | --- |
| `alice@customer.com` | `u_7f3ac9@customer.com` |
| `4111 1111 1111 1111` | `4111 1193 7420 8846` — Luhn-valid, BIN kept |
| `sk_live_4eC39HqLyj` | `sk_live_9mB71TzKnQ` |
| `+1 (555) 867-5309` | `+7 (204) 331-8874` |

The mapping is one-way — HMAC, not encryption. There is no route from a
surrogate back to the original, and anyone holding the key can confirm a guess,
so **the key must not travel with the logs**. Leave `redactor.pseudonymization.key`
null to derive one from `APP_KEY` (never used directly). Rotating it changes
every surrogate, which is how you deliberately break correlation with logs
already exported.

Without a usable key, `surrogate` and `hash` fall back to plain redaction rather
than emitting an unkeyed stand-in that would look joinable and silently not be.

Surrogates are the same on every profile, so an audit channel on `strict` and an
application channel on `observability` can still be joined on the same user. A
profile that must not be linkable back sets its own salt:

```php
'export' => [
    'pseudonymization' => ['salt' => 'export-2026'],
    // ...
],
```

The shipped `observability` profile is set up for this.

### Reversible tokens

A surrogate is one-way. A token is a surrogate the *application* can exchange
back, which is what the boundary in front of a language model needs: the model
sees `tok_email_k4m9rp2xzq`, refers to it in its answer, and the application
resolves it before acting.

```php
'operators' => ['email' => 'tokenize', 'credit_card' => ['tokenize' => ['ttl' => 600]]],
```

```php
$prompt = Redactor::redact($ticket, 'ai');          // 'reply to tok_email_k4m9rp2xzq about ...'
$answer = $llm->complete($prompt);                   // the model reasons about the token
$action = Redactor::detokenize($answer);             // 'reply to alice@customer.com about ...'
```

Tokens are derived with the pseudonymisation key, so they are stable and
cannot be guessed. Originals are kept in the cache, encrypted with the
application key, for `redactor.tokenization.ttl` seconds; a token the store no
longer knows, or one a model invented, is left exactly as it is. Anyone holding
the cache and the application key can resolve tokens, which is the trust the
application itself already carries.

## Confidence

Binary matching forces a choice between noise and misses: the only way to quieten
a rule is to weaken its regex everywhere. Detections carry a score instead.

```php
'patterns' => [
    'card' => ['pattern' => '/\b\d{16}\b/', 'confidence' => 0.3, 'validator' => 'luhn'],
],

'min_confidence' => 0.5,
```

The base score comes from the rule; a passing checksum and a credential keyword
beside the match raise it. So the same pattern is filtered out as noise on its
own and reported when something corroborates it — without editing the pattern.

Entropy detections are scored the same way: medium on their own, higher the
further the token sits above its threshold, and higher again beside a keyword.
A value found by its key is certain. `min_confidence` applies to all of them.

Every finding explains itself:

```json
{
  "rule": "card",
  "confidence": 0.87,
  "severity": "medium",
  "signals": [
    "base +0.30 (pattern \"card\" matched)",
    "validator +0.75 (luhn checksum passed)",
    "context +0.25 (a credential keyword appears alongside the match)"
  ]
}
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

`RedactorFormatter` is still available for channels that want a self-contained
drop-in. It owns the output format, so prefer the tap unless you specifically
want that. It can wrap an inner formatter rather than replace it:

```php
use Kirschbaum\Redactor\Logging\RedactorFormatter;
use Monolog\Formatter\JsonFormatter;

$handler->setFormatter(new RedactorFormatter(new JsonFormatter));
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

// Throwables, DateTimeInterface, DateTimeZone, enums and closures pass
// through untouched: a Throwable has nothing to inspect and the formatter
// needs the object to render the trace. Key rules still apply to them.
Log::error('failed', ['exception' => $e, 'password' => 'x']);
// ['exception' => $e, 'password' => '[REDACTED]']

// Non-serializable objects (configurable behavior)
$resource = fopen('file.txt', 'r');
$redacted = Redactor::redact(['file' => $resource]);
// Behavior controlled by 'non_redactable_object_behavior' setting
```

### Custom Strategies

Create your own redaction logic with full type safety:

```php
use Kirschbaum\Redactor\Strategies\Contracts\Strategy;
use Kirschbaum\Redactor\RedactionContext;

class InternalDataStrategy implements Strategy
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
$profiles = Redactor::profiles();
$exists = Redactor::hasProfile('custom_profile');
```

## HTTP Responses

Data that leaves through an API needs the same boundary as data that leaves
through a log. The `redact` middleware redacts a response before it is sent,
with a profile per route:

```php
Route::get('/export', ExportController::class)->middleware('redact:observability');
Route::get('/me', MeController::class)->middleware('redact');
```

JSON responses are redacted as data, so structure and types survive; text
responses are redacted as text; file responses pass through. The profile's
`_redacted` markers are never written into a response. Where a consumer has
typed the field - an API contract, MCP structured content - use `nullify` so
the field stays a field and keeps its type:

```php
'operators' => ['ssn' => 'nullify', 'age' => 'nullify'],
```

The middleware fails closed: a response that cannot be redacted becomes a 500
with none of the original body, not the original body. Run `redactor:validate`
at deploy time so that never happens in production.

### Streams

A streamed response - server-sent events, a model's tokens, a file piped
through - is redacted as it streams. The middleware wraps the callback; for
anything else, wrap the chunks yourself:

```php
use Kirschbaum\Redactor\Streaming\StreamRedactor;

$stream = new StreamRedactor(app(Redactor::class), 'observability');

foreach ($stream->through($llm->tokens()) as $safe) {
    echo $safe;                       // emitted only once it cannot be half a secret
}

return $stream->response(fn () => $this->export($rows));   // a StreamedResponse
```

The last kilobyte of input (configurable) is held back until more arrives, so a
secret split across two chunks is still caught, and the cut always falls on a
line end - or, when a stream goes a whole window without one, a word boundary.
An open PEM block is held whole. The cost is latency in bytes, not time.

## MCP Servers

An MCP server hands data straight to a model. With Laravel's MCP package,
one trait redacts everything the server returns, over HTTP or stdio: tool
results, structured content, resource reads, prompt messages, streamed tool
output and error messages. Binary content and the protocol envelope are left
alone.

```php
use Kirschbaum\Redactor\Mcp\RedactsResponses;

class SupportServer extends Server
{
    use RedactsResponses;

    protected function redactionProfile(): ?string
    {
        return 'observability';    // or a profile that tokenises, see below
    }
}
```

It sits where the server builds its responses, so the package's own test
helpers exercise it: `SupportServer::tool(LookupCustomer::class)->assertDontSee($email)`.

## AI Agents

With Laravel's AI package, the `RedactPrompt` middleware redacts a prompt
before the provider sees it and resolves tokens in the answer on the way back:

```php
use Kirschbaum\Redactor\Ai\RedactPrompt;

class SupportAgent extends Agent implements HasMiddleware
{
    public function middleware(): array
    {
        return [RedactPrompt::using('ai')];
    }
}
```

With a profile whose operators tokenise, the model reasons about
`tok_email_k4m9rp2xzq` and the application receives the real address back in
the response text. With a profile that redacts outright, the model never sees
the value. Pass `detokenizeResponse: false` to keep tokens in the answer.

## Events

Every redaction that changed something dispatches `RedactionPerformed` with
the profile, the keys, and counts per rule and per entity, and never a value,
so a listener can feed metrics or an audit trail without becoming a leak. A
listener that throws never breaks the redaction. `REDACTOR_EVENTS=false`
switches it off.

```php
Event::listen(RedactionPerformed::class, fn ($e) => Metrics::increment('redactions', $e->findings, ['profile' => $e->profile]));
```

## Where Else To Use It

The Monolog tap covers the log channel. The same call covers everything else
an application emits:

```php
// A queued export, on a profile that pseudonymises
ExportRow::create(Redactor::redact($user->toArray(), 'observability'));

// A support transcript before it reaches a third party
$client->createTicket(Redactor::redact($conversation, 'strict'));

// The prompt sent to a language model
$prompt = Redactor::redact($userMessage, 'observability');

// An error reporter's outgoing payload, in whichever hook it offers
$reporter->beforeSend(fn (array $event) => Redactor::redactSafely($event, 'strict'));

// A debug endpoint
return response()->json(Redactor::redact($state, 'performance'));
```

`redactSafely()` never throws and fails closed, which is what a hook inside
someone else's error path needs. Every path above accepts a profile name, so
the same value can be pseudonymised on one channel and removed on another.

## Built-in Profiles

- **`default`**: Balanced redaction for general logging and debugging
- **`strict`**: Aggressive redaction for sensitive contexts and audit trails
- **`observability`**: Pseudonymises rather than redacts, so logs stay joinable
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
REDACTOR_MIN_CONFIDENCE=0.0
REDACTOR_PSEUDONYMIZATION=true
REDACTOR_PSEUDONYMIZATION_KEY=
REDACTOR_PSEUDONYMIZATION_SALT=
REDACTOR_SHANNON_ENABLED=true
REDACTOR_SHANNON_THRESHOLD=4.8
REDACTOR_SHANNON_MIN_LENGTH=25
REDACTOR_RECOGNITION=false
REDACTOR_RECOGNITION_URL=http://127.0.0.1:5002/analyze

# File scanning
REDACTOR_SCAN_PROFILE=file_scan
REDACTOR_SCAN_MAX_FILE_SIZE=10485760
REDACTOR_SCAN_SKIP_BINARY=true
REDACTOR_SCAN_RESPECT_GITIGNORE=true
REDACTOR_SCAN_BASELINE=.redactor-baseline.json
REDACTOR_SCAN_WINDOW_LINES=512
REDACTOR_SCAN_OVERLAP_LINES=4
REDACTOR_SCAN_VERIFY=false
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

Findings are ranked by severity, so the certain ones are read first.

### Looking through encodings

A secret in a repository is often not written plainly. A credential URL in a
JSON file reads `https:\/\/user:pass@host`, a key in a Kubernetes secret is
base64, a token in a query string is percent-encoded. The scanner decodes
those, one layer deep, and scans what comes out; a finding says which encoding
hid it and its excerpt is taken from the decoded, redacted text. Switch it off
with `REDACTOR_SCAN_DECODE=false`. Redaction of live payloads does not decode:
that is a cost on every log line for a case the scanner is the right place to
catch.

### Scanning changes, not files

A gate on commits cares about what is being added, not what was already
there. Three modes scan only the lines a change adds, so a pre-existing finding
never blocks a commit and a secret is caught on the line that introduces it:

```bash
php artisan redactor:scan --staged                 # what is about to be committed
php artisan redactor:scan --diff=origin/main       # what this branch adds over main
php artisan redactor:scan --history                # every line every commit ever added
php artisan redactor:scan --history=main..HEAD app/  # a range, and a pathspec
```

History mode finds a secret that a later commit removed: it is still in the
repository. Each finding names the commit that added it.

### As a gate

Publish the hook and the workflow:

```bash
php artisan vendor:publish --tag=redactor-ci
git config core.hooksPath .githooks
```

The hook runs `redactor:scan --staged --bail` before every commit. The
workflow scans a pull request's changes over its base and uploads SARIF, and
scans the whole tree against the baseline on `main`. `--output=junit` produces
JUnit XML for a CI dashboard that already renders test results: one test case
per file, one failure per finding, with the excerpt already redacted.

Files that are binary, larger than `max_file_size`, matched by an exclude
pattern, or already ignored by git are skipped. Everything else is read as
overlapping windows of lines, so memory stays flat whatever the file size — the
files most worth scanning are the large ones. Windows overlap so a secret
spanning a boundary (a PEM block, a wrapped connection string) is still found.

### Confidence filtering

```bash
php artisan redactor:scan --min-confidence=0.8
```

Raises the bar without weakening any pattern. Each finding reports its score,
its severity and the signals behind it, so the threshold can be chosen on
evidence.

### Verifying credentials

A scan of a mature repository turns up hundreds of candidates — expired keys,
examples in docs, fixtures, rotated credentials — and a list that cannot
separate the live ones from the dead is a list nobody triages. Verification asks
each provider directly.

It also sends real secrets to third parties, so nothing happens unless all three
of these agree:

```php
// config/redactor.php — reviewable in a diff
'verification' => [
    'enabled' => true,
    'verifiers' => ['github_token', 'stripe_key', 'slack_token'],
],
```

```bash
php artisan redactor:scan --verify   # and a human, per run
```

An empty `verifiers` list means none: enabling the feature and choosing who to
trust with the secrets are separate decisions. The command names every host it
will contact before it contacts any of them. Redaction itself can never trigger
this — only the scan command can, because nothing running unattended inside an
application should be making outbound calls with secrets in them.

A confirmed-live credential is ranked `LIVE` above everything else. A check that
could not complete stays `high`, not `low`: failing to verify is not evidence of
safety. The secret never reaches a finding, so it cannot escape through JSON,
SARIF or a baseline file.

### CI

`--output=sarif` produces SARIF 2.1.0, which GitHub renders inline on the pull
request:

```yaml
- run: php artisan redactor:scan --output=sarif > redactor.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: redactor.sarif
```

### Suppressing a finding in place

A fixture, a documented example, a sandbox credential: mark the line and the
scanner skips it, with the reason next to the code rather than in a baseline
file.

```php
$stripe = 'sk_test_4eC39HqLyjWDarjtT1zdp7dc'; // redactor:allow - Stripe's public test key
```

### Ruleset fingerprint

Every scan reports a short fingerprint of the rules it ran: in JSON, in SARIF
under the tool's properties, and in the baseline it writes. Two runs with the
same fingerprint are comparable; a baseline generated under a different one is
warned about, since what it accepted may no longer mean the same thing.

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
- Laravel 12.x or 13.x

## Installation

```bash
composer require kirschbaum-development/redactor
php artisan vendor:publish --tag=redactor-config
```

## Testing

```bash
composer test           # full suite, in parallel
composer test-coverage  # with the coverage floor enforced
composer lint           # Pint, Rector, PHPStan (level 10, no baseline)
composer rector:check   # what Rector would change, without changing it
composer mutate         # mutation testing (Pest); local only, not run in CI
composer preflight      # everything CI runs
```

Coverage and mutation testing need a coverage driver (pcov or Xdebug) loaded
in the CLI; without one Pest reports no coverage and generates no mutations.
Both scripts raise the memory limit, which the coverage report needs.

### In your own test suite

Redaction is a runtime promise, and a promise nobody tests is one that quietly
stops being kept. `Redactor::fake()` swaps in a redactor that still redacts
but remembers every call, so a test can say the thing that matters:

```php
use Kirschbaum\Redactor\Facades\Redactor;

$fake = Redactor::fake();          // before the code under test logs anything

$this->postJson('/login', ['email' => 'bob@example.com', 'password' => 'hunter2']);

$fake->assertNeverEmitted('hunter2', 'bob@example.com');  // across every call and profile
$fake->assertRedacted('password');
$fake->assertFinding('email');
$fake->assertProfileUsed('strict');
```

`assertNeverEmitted()` checks everything the redactor produced, whichever path
it took - the log tap, a queued export, a response. Install the fake before a
log channel is first used, because the tap resolves the redactor when the
channel is built.

## Roadmap

Done since the last release: partial (span-level) replacement, a Monolog
processor integration, structured scan findings with SARIF output and baselines,
checksum validators, and per-alphabet entropy thresholds.

Since then: compiled path rules, deterministic pseudonymisation with
format-preserving surrogates, confidence scoring, streaming file scanning, and
opt-in credential verification.

Still open:

- Reversible tokenisation against an external vault
- More built-in verifiers (AWS, GCP, Azure, Twilio)
- An in-process ONNX recogniser, so entity recognition needs no sidecar
- Batching every candidate string in a payload into one recogniser call

## License

MIT License. See [LICENSE.md](LICENSE.md) for details.

