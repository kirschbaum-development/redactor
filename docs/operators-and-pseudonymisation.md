# Operators and Pseudonymisation

- [Introduction](#introduction)
- [Configuring Operators](#configuring-operators)
- [The Operators](#the-operators)
- [Precedence](#precedence)
- [Pseudonymisation](#pseudonymisation)
    - [Surrogates](#surrogates)
    - [The Key and the Salt](#the-key-and-the-salt)
    - [Cross-Profile Stability](#cross-profile-stability)
- [Reversible Tokens](#reversible-tokens)
    - [Detokenizing](#detokenizing)
    - [The Token Store](#the-token-store)
- [Trust Model](#trust-model)

## Introduction

Detection asks "is this sensitive". An operator answers "so what". They are separate because the right answer differs by context for the very same value: an email in an audit log wants a stable surrogate so the log stays joinable, the same email in a support export wants deleting, and in a secret scan it wants reporting and nothing else.

Operators are chosen per *entity*, the kind of thing that was found, rather than per rule. Every detector goes through the same policy: a value found by its key uses the lowercased key name as its entity, a high-entropy token has the entity `high_entropy`, a known secret has `known_secret`, a pattern match has whatever its rule's `entity` says.

## Configuring Operators

A profile's `operators` block maps entities to operators, with `default` for everything else:

```php
'operators' => [
    'default'     => 'redact',
    'email'       => ['surrogate' => ['preserve_domain' => true]],
    'credit_card' => ['partial' => ['keep' => 4]],
    'ssn'         => 'nullify',
],
```

An operator is written in any of three spellings, depending on how much you are saying:

```php
'redact'                                // just the name
['partial' => ['keep' => 4]]            // the name mapped to its options
['operator' => 'partial', 'keep' => 4]  // the name as a key beside its options
```

The same spellings work in a pattern rule's `operator` option and as the value of a path rule. An operator name that is not registered is not caught when the profile is built: at redaction time the value is redacted with the replacement string and a warning names the operator, the profile and the rule.

## The Operators

| Operator | `alice@customer.com` becomes | Options |
| --- | --- | --- |
| `redact` | `[REDACTED]` | none; writes the profile's `replacement` |
| `mask` | `******************`, length preserved | `mask_character` (default `*`) |
| `partial` | `**************.com`, last N kept | `keep` (default 4), `mask_character` |
| `remove` | deleted | none |
| `nullify` | `null` in a field; deleted inside a string | none |
| `hash` | `[email:k4m9rp2xzq]` | `length` (4 to 64, default 10), `labelled` (default true) |
| `surrogate` | `u_7f3ac9@customer.com` | depends on the generator, see [Surrogates](#surrogates) |
| `tokenize` | `tok_email_k4m9rp2xzq` | `ttl` in seconds |
| `preserve` | `alice@customer.com`, reported and unchanged | none |

A few of them deserve a note:

**`nullify`** exists for typed fields. `[REDACTED]` in an integer field breaks every consumer that typed it, and `remove` breaks the ones that require the key. Null keeps both honest: the field is there, it has no value. Where a consumer has typed the field, an API contract or MCP structured content, use `nullify`. Inside a string there is no null to write, so a span found by a pattern is deleted as `remove` would.

**`hash`** produces a stable keyed token that is obviously not real data, for places where a format-preserving surrogate might be mistaken for the genuine value. With `labelled` false it is the bare token.

**`preserve`** is not a no-op. It lets a scan profile detect and report without rewriting anything, and lets one path rule carve an exception out of a broader one. A preserved finding appears in `inspect()` without marking the payload redacted.

`hash`, `surrogate` and `tokenize` need a pseudonymisation key. Without one they fall back to `redact` rather than emit an unkeyed stand-in that would look joinable and silently not be.

Register your own with `Redactor::registerOperator('classify', $operator)` and use it from config by name. See [Extending](extending.md#operators).

## Precedence

When a detection has more than one candidate operator, the most specific wins:

1. The **path** it was found at, when a path rule matched.
2. The **entity** it is: `operators.<entity>`.
3. The **rule** that found it, when the rule explicitly set `operator` or a non-default `mode`.
4. The profile **default**: `operators.default`, or `redact` when that is absent.

Entity beats rule deliberately. "Every email here becomes a surrogate" is a policy decision about data, and which regex spotted it is an implementation detail. Rule beats default only when the rule actually chose something: a rule's `mode` defaults to `replace`, and treating that default as a choice would make `operators.default` unreachable for anything found by a pattern.

## Pseudonymisation

Replacing every value with `[REDACTED]` collapses distinct values into one, which destroys the questions logs exist to answer: how many users hit this, is it always the same account, did this session span both services.

`surrogate`, `hash` and `tokenize` replace a value with a *stable* stand-in instead. The same input always produces the same output, so counts, joins and traces survive:

```php
Redactor::redact('login by alice@customer.com', 'observability');
// 'login by u_7f3ac9@customer.com'

Redactor::redact('logout for alice@customer.com', 'observability');
// 'logout for u_7f3ac9@customer.com'   same surrogate, still joinable
```

Inputs are normalised before they are keyed, so `Bob@Example.COM ` and `bob@example.com` produce the same surrogate rather than double-counting one user.

### Surrogates

A surrogate preserves the shape of the value it replaces, so anything downstream that parses the value keeps parsing it. The `surrogate` operator picks the first generator that supports the value:

| Generator | Supports | Example | Options |
| --- | --- | --- | --- |
| `EmailSurrogate` | entity `email`, or a value with exactly one `@` | `alice@customer.com` to `u_7f3ac9@customer.com` | `preserve_domain` (default true). When false the domain becomes `example.invalid`, which can never resolve. |
| `CreditCardSurrogate` | entity `credit_card`, or 12 to 19 digits | `4111 1111 1111 1111` to `4111 1193 7420 8846`, Luhn-valid, spacing kept | `preserve_bin` (default 6). Digits of the issuer prefix to keep. |
| `CharacterClassSurrogate` | everything | `sk_live_4eC39HqLyj` to `sk_live_9mB71TzKnQ`; `+1 (555) 867-5309` to `+7 (204) 331-8874` | `preserve_prefix` (default 0). Leading bytes to keep verbatim. |

`CharacterClassSurrogate` replaces each letter and digit with another of the same class and leaves separators, punctuation and multibyte characters alone. Length, capitalisation and digit positions survive; nothing of the original does except its shape. It is the fallback for every entity nobody wrote a generator for. To add one, see [Extending](extending.md#surrogate-generators).

Keeping an email's domain preserves the analysis people run on logs: which tenant, which provider, how many distinct users at one company. Keeping a card's BIN preserves the issuer and card type, which fraud and finance teams aggregate on and which is not specific to a cardholder.

### The Key and the Salt

The mapping is one-way: an HMAC, not encryption. There is no route from a surrogate back to the original, but anyone holding the key can confirm a guess, so **the key must not travel with the logs**.

```php
'pseudonymization' => [
    'enabled' => env('REDACTOR_PSEUDONYMIZATION', true),
    'key'     => env('REDACTOR_PSEUDONYMIZATION_KEY'),
    'salt'    => env('REDACTOR_PSEUDONYMIZATION_SALT'),
],
```

Leave `key` null to derive one from `APP_KEY`. The derivation is an HMAC over a fixed label, so `APP_KEY` itself is never used directly and a leaked surrogate corpus cannot be turned against anything else signed with it. An explicit key must be at least 16 bytes; a shorter one throws a `PseudonymizationKeyException`, which the operators catch and log before falling back to plain redaction.

Rotating the key changes every surrogate. That is the intended way to break correlation with logs already exported, and the reason not to rotate it casually.

Without a usable key, because pseudonymisation is disabled, `APP_KEY` is empty, or the key is too short, `surrogate`, `hash` and `tokenize` fall back to plain redaction and a warning is logged once per redaction.

### Cross-Profile Stability

The salt is shared by every profile, so the same user gets the same surrogate on every channel and an audit log on `strict` can be joined with an application log on `observability`. The entity is part of the seed, so the same string found as an `email` and as a `phone` gets different surrogates.

A profile that must not be linkable back sets its own salt:

```php
'export' => [
    'pseudonymization' => ['salt' => 'export-2026'],
    // ...
],
```

A profile can also set `'pseudonymization' => ['enabled' => false]` to fall back to plain redaction for that profile alone.

## Reversible Tokens

A surrogate is one-way. A token is a surrogate the *application* can exchange back, which is what the boundary in front of a language model needs: the model sees `tok_email_k4m9rp2xzq`, refers to it in its answer, and the application resolves it before acting.

```php
'operators' => [
    'email'       => 'tokenize',
    'credit_card' => ['tokenize' => ['ttl' => 600]],
],
```

```php
$prompt = Redactor::redact($ticket, 'ai');  // 'reply to tok_email_k4m9rp2xzq about ...'
$answer = $llm->complete($prompt);           // the model reasons about the token
$action = Redactor::detokenize($answer);     // 'reply to alice@customer.com about ...'
```

A token is `tok_<entity>_<id>`: the entity lowercased with anything that is not a letter or digit collapsed to `_`, then a 12-character id derived with the pseudonymisation key. It is spelt to survive a model: one word, no punctuation a tokenizer would split on, an entity name a model can reason about. Tokens are stable, so the same address yields the same token in every prompt, and they cannot be guessed.

The original goes into the token store, encrypted with the application key, for `ttl` seconds. The operator's `ttl` option overrides the global `tokenization.ttl`; a `ttl` of null keeps the original forever.

### Detokenizing

`Redactor::detokenize()` walks a string or an array and replaces every token the store knows:

```php
Redactor::detokenize('reply to tok_email_k4m9rp2xzq');  // 'reply to alice@customer.com'
Redactor::detokenize(['text' => 'tok_email_k4m9rp2xzq', 'n' => 1]);
```

A token the store does not know, whether expired, from another application, or invented by the model, is left exactly as it is, since guessing would be worse. Content that is neither a string nor an array is returned unchanged.

### The Token Store

Originals live in the application cache under the `redactor:token:` prefix, encrypted with `APP_KEY` before they are written:

```php
'tokenization' => [
    'store' => env('REDACTOR_TOKEN_STORE'),   // null for the default cache store
    'ttl'   => env('REDACTOR_TOKEN_TTL', 86_400),
],
```

A cache entry that fails to decrypt, after a key rotation or corruption, is treated as unknown. The store is resolved lazily the first time a `tokenize` operator runs, so the redactor can be built before the cache and encrypter are ready.

`Kirschbaum\Redactor\Tokenization\TokenStore` is the contract for another backing store, a vault or a table. Bind your implementation to that interface in the container. See [Extending](extending.md#token-stores).

## Trust Model

Three things hold the mapping between a stand-in and its original, and they carry different trust:

| Stand-in | Reversible by | Needs |
| --- | --- | --- |
| `hash`, `surrogate` | nobody | the key, to confirm a guess |
| `tokenize` | the application | the token store and `APP_KEY` |
| `redact`, `mask`, `partial`, `remove`, `nullify` | nobody | nothing |

Anyone holding the cache and the application key can resolve tokens, which is the trust the application itself already carries. Anyone holding the pseudonymisation key can confirm whether a given email produced a given surrogate, which is why the key stays with the application and never with the logs. Tokens and surrogates are derived with the same key, so rotating it invalidates both.
