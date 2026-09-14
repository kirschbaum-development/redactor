# Extending

- [Introduction](#introduction)
- [Contracts at a Glance](#contracts-at-a-glance)
- [Strategies](#strategies)
    - [The Strategy Contract](#the-strategy-contract)
    - [The Marker Interfaces](#the-marker-interfaces)
    - [A Worked Custom Strategy](#a-worked-custom-strategy)
    - [Registering a Strategy](#registering-a-strategy)
    - [What a Strategy Can Reach](#what-a-strategy-can-reach)
- [Detectors](#detectors)
- [Operators](#operators)
    - [A Worked Custom Operator](#a-worked-custom-operator)
- [Surrogate Generators](#surrogate-generators)
- [Recognizers](#recognizers)
- [Verifiers](#verifiers)
- [Token Stores](#token-stores)
- [Macros](#macros)

## Introduction

The package has one seam for each thing it does: a strategy for a step in the chain, a detector for finding spans, an operator for replacing them, a generator for shaping a surrogate, a recogniser for asking a model, a verifier for asking a provider, and a token store for keeping originals. Each is an interface under `Kirschbaum\Redactor`, and each is registered in one place.

## Contracts at a Glance

| Contract | Answers | Registered with |
| --- | --- | --- |
| `Strategies\Contracts\Strategy` | Should I handle this value, and what replaces it? | `custom_strategies` config, or `Redactor::registerCustomStrategy()` |
| `Detection\Detector` | Where in this string is something sensitive? | Implement it on a strategy |
| `Operators\Operator` | What replaces a detected span? | `Redactor::registerOperator()` |
| `Operators\Surrogates\SurrogateGenerator` | What does a fake of this value look like? | `SurrogateFactory::register()` |
| `Recognition\Recognizer` | Where are the names and places in this prose? | `Redactor::registerRecognizer()` |
| `Verification\Verifier` | Is this credential still live? | The `SecretVerifier` constructor |
| `Tokenization\TokenStore` | Where does a token's original live? | Bind in the container |

## Strategies

### The Strategy Contract

A strategy is one step of the chain a value passes through:

```php
namespace Kirschbaum\Redactor\Strategies\Contracts;

use Kirschbaum\Redactor\RedactionContext;

interface Strategy
{
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool;

    public function handle(mixed $value, string $key, RedactionContext $context): mixed;
}
```

`shouldHandle()` is asked for every value, scalar and container alike, with the key it sits under (`''` for a bare string or the root). When it returns true, `handle()` returns what should stand in the value's place. By default the chain stops there and the walk does not descend, so a strategy that returns a container has ended the matter for everything inside it.

### The Marker Interfaces

Four empty interfaces in the same namespace change how the chain treats a strategy:

| Marker | Effect |
| --- | --- |
| `ChainableStrategy` | `handle()` rewrote part of the value rather than replacing it, so the strategies after it still run on what it returned. `LargeStringStrategy` is one. |
| `DetectingStrategy` | Extends `ChainableStrategy`. `handle()` returns the value untouched and reports what it found through `$context->collect()`. Every detecting strategy sees the same original string, and the context rewrites it once after the last of them. `RegexPatternsStrategy`, `ShannonEntropyStrategy`, `KnownSecretsStrategy` and `EntityRecognitionStrategy` are these. |
| `PreservingStrategy` | `handle()` declares the value safe. The chain ends, the walk does not descend, and any pending detections are discarded. `SafeKeysStrategy` is one. |
| `ConditionalStrategy` | Adds `appliesTo(RedactorConfig $config): bool`. A strategy returning false is left out of the chain for that profile, so it costs nothing. `EntityRecognitionStrategy` uses it to stay inert until enabled. |
| `PrimingStrategy` | Adds `prime(mixed $content, RedactionContext $context): void`, called once with the whole payload before the walk starts. For work that costs per call rather than per value: do it here in one go and leave the result on the context for `handle()` to read. `EntityRecognitionStrategy` uses it to recognise every prose value in one request. |

Implement the markers that describe what your `handle()` does. A strategy with none of them replaces the value outright and ends the chain.

### A Worked Custom Strategy

A strategy that redacts anything under a key that starts with `internal_` or `debug_`:

```php
namespace App\Redaction;

use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\Strategies\Contracts\Strategy;

class InternalDataStrategy implements Strategy
{
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        return str_starts_with($key, 'internal_') || str_starts_with($key, 'debug_');
    }

    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        // recordRedaction() sets the flag, adds the key to redactedKeys, and
        // reports a finding under the given rule name. markRedacted() would
        // set the flag alone.
        $context->recordRedaction($key, 'internal_data');

        return '[INTERNAL]';
    }
}
```

A strategy that wants the operator policy, so the profile decides what happens, builds a `Detection` and hands it to the context instead of choosing a replacement itself:

```php
use Kirschbaum\Redactor\Detection\Confidence;
use Kirschbaum\Redactor\Detection\Detection;

public function handle(mixed $value, string $key, RedactionContext $context): mixed
{
    if (! is_string($value) || $context->isAllowed($value)) {
        return $value;
    }

    $detection = new Detection(
        entity: 'internal',
        rule: 'internal_data',
        offset: 0,
        value: $value,
        confidence: Confidence::of(Confidence::CERTAIN, 'the key names internal data'),
        key: $key,
    );

    $context->recordDetection($detection);

    return $context->operate($detection);
}
```

`operate()` resolves the operator through the same precedence as every shipped strategy and never throws.

### Registering a Strategy

Register the class under a short name in `custom_strategies`, then list the name in a profile's `strategies` wherever it should run:

```php
'custom_strategies' => [
    'internal_data' => \App\Redaction\InternalDataStrategy::class,
],

'profiles' => [
    'default' => [
        'strategies' => [
            \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
            'internal_data',
            \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
            // ...
        ],
    ],
],
```

Or register an instance at runtime, which also lets you pass constructor arguments:

```php
Redactor::registerCustomStrategy('internal_data', new InternalDataStrategy($settings));
```

A name registered at runtime takes precedence over the config entry of the same name, and registering one drops the cached strategy chains so the next redaction picks it up. Classes are instantiated without arguments from config, so a strategy that needs dependencies is registered at runtime. Custom strategies are cloned into each chain.

A profile may also list a fully qualified class name directly, without registering it, as the shipped profiles do.

### What a Strategy Can Reach

`RedactionContext` is what a strategy is handed. The parts meant for strategies:

| Member | Use |
| --- | --- |
| `$context->config` | The resolved `RedactorConfig`: `replacement`, `patterns`, `minConfidence`, `shannonEntropy`, `recognition` and so on. |
| `$context->operate(Detection $detection, ?OperatorSpec $atLocation = null)` | Apply the configured operator to a detection and return the replacement text. |
| `$context->operatorSpecFor(Detection $detection)` | Which operator would apply, without applying it. |
| `$context->collect(Detection $detection)` | Hold a detection for resolution, from a `DetectingStrategy`. |
| `$context->isAllowed(string $value)` | Whether the profile allow-list excuses the value. |
| `$context->recordRedaction(string $key, ?string $rule, int $offset, int $length, string $matched, ?string $entity, ?Confidence $confidence, bool $redacted)` | Record that something was redacted under a key and report a finding. |
| `$context->recordDetection(Detection $detection, bool $redacted = true)` | The same, from a detection. |
| `$context->markRedacted()` | Set the redaction flag alone. |
| `$context->secrets()` | The known secrets in play, profile and runtime. |
| `$context->pseudonymizer()` | The profile's pseudonymizer, or null. |
| `$context->recognizers()` | The recogniser registry. |
| `$context->getCachedEntropy()`, `cacheEntropy()` | The per-redaction entropy cache. |

## Detectors

`Detection\Detector` is the contract for anything that can find sensitive spans in a string:

```php
namespace Kirschbaum\Redactor\Detection;

use Kirschbaum\Redactor\RedactionContext;

interface Detector
{
    /** @return array<int, Detection> offsets relative to $subject as given */
    public function detect(string $subject, string $key, RedactionContext $context): array;
}
```

A detector reads; it never writes. It reports every span it believes is sensitive with an entity, a rule name, a byte offset into the subject exactly as received, the matched text and a `Confidence`, and leaves the decisions to the context. The shipped detecting strategies implement both `Strategy` and `Detector`, with `handle()` collecting whatever `detect()` returns:

```php
class MyDetector implements DetectingStrategy, Detector, Strategy
{
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        return is_string($value);
    }

    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        foreach ($this->detect($value, $key, $context) as $detection) {
            $context->collect($detection);
        }

        return $value;
    }

    public function detect(string $subject, string $key, RedactionContext $context): array
    {
        // ...
    }
}
```

Build a `Confidence` with `Confidence::of($score, $reason)` and add signals with `->with($name, $delta, $reason)`. `KeywordContext::boost($confidence, $subject, $offset, $key)` adds the shared context signal. Where the detector fails and the value cannot be trusted, return `[Detection::failClosed($entity, $rule, $subject, $key, $reason)]`, which replaces the whole value whatever the operator policy says.

## Operators

An operator produces the text that replaces a detected span:

```php
namespace Kirschbaum\Redactor\Operators;

use Kirschbaum\Redactor\Detection\Detection;

interface Operator
{
    public function apply(Detection $detection, OperatorContext $context): string;
}
```

Whether anything changed is decided by comparing the returned text with the detected value: an operator that returns `$detection->value` unchanged, as `preserve` does, has its finding reported without the payload being marked redacted. `OperatorContext` is deliberately narrow: an operator receives the profile's `replacement`, its own `options` and a lazily resolved pseudonymizer, and nothing else. It cannot reach the payload, the profile or the container, which keeps it testable in isolation and impossible to turn into a second detection layer.

### A Worked Custom Operator

An operator that replaces a value with its category, so a log says `<email>` rather than `[REDACTED]`:

```php
namespace App\Redaction;

use Kirschbaum\Redactor\Detection\Detection;
use Kirschbaum\Redactor\Operators\Operator;
use Kirschbaum\Redactor\Operators\OperatorContext;

class ClassifyOperator implements Operator
{
    public function apply(Detection $detection, OperatorContext $context): string
    {
        $open = $context->stringOption('open', '<');
        $close = $context->stringOption('close', '>');

        return $open.$detection->entity.$close;
    }
}
```

Register it, in a service provider's `boot()`, and use it from config by name:

```php
Redactor::registerOperator('classify', new ClassifyOperator);
```

```php
'operators' => [
    'default' => 'classify',
    'phone'   => ['classify' => ['open' => '[', 'close' => ']']],
],
```

`OperatorContext` exposes the profile's `replacement` and the raw `options` array as public properties, offers `intOption()`, `boolOption()` and `stringOption()`, each returning the default when the option is absent or the wrong type, and `pseudonymizer()` for an operator that needs a stable mapping. An operator that pseudonymises should return `$context->replacement` when `pseudonymizer()` is null, as the shipped ones do, rather than emit an unkeyed stand-in.

Registering a name that already exists replaces the built-in operator, so an application can, for example, swap `tokenize` for one backed by a vault.

## Surrogate Generators

The `surrogate` operator asks a `SurrogateFactory` for the first generator that supports the value. Add one for a domain type the package has never heard of, a policy number, an NHS number, an internal account format:

```php
namespace App\Redaction;

use Kirschbaum\Redactor\Operators\Surrogates\SurrogateGenerator;
use Kirschbaum\Redactor\Support\DeterministicRandom;

class PolicyNumberSurrogate implements SurrogateGenerator
{
    public function supports(string $entity, string $value): bool
    {
        return $entity === 'policy_number';
    }

    public function generate(string $value, DeterministicRandom $random, array $options = []): string
    {
        return 'POL-'.$random->token(8, 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789');
    }
}
```

`DeterministicRandom` is a keyed, reproducible stream seeded from the value, so the same input yields the same surrogate on any machine. It offers `byte()`, `below($bound)`, `pick($alphabet)`, `digit()` and `token($length, $alphabet)`.

Generators are registered ahead of the built-in ones on the factory, and the factory is given to the `SurrogateOperator`, which is registered under `surrogate`:

```php
use Kirschbaum\Redactor\Operators\SurrogateOperator;
use Kirschbaum\Redactor\Operators\Surrogates\SurrogateFactory;

$factory = new SurrogateFactory([new PolicyNumberSurrogate]);

Redactor::registerOperator('surrogate', new SurrogateOperator($factory));
```

`CharacterClassSurrogate` supports everything and stays last, so a generator that claims a value wins over it.

## Recognizers

Implement `Recognition\Recognizer` and register it with `Redactor::registerRecognizer()`. [Entity Recognition](entity-recognition.md#writing-a-recognizer) has the full contract and a worked example.

## Verifiers

A verifier asks one provider whether one credential is live:

```php
namespace Kirschbaum\Redactor\Verification;

interface Verifier
{
    public function name(): string;

    public function host(): string;

    public function supports(string $entity, string $rule): bool;

    public function verify(string $secret): VerificationResult;
}
```

`name()` is what goes in `scan.verification.verifiers`. `host()` is announced before any request is sent. `verify()` must never throw or log the secret, and returns `VerificationResult::active()`, `::inactive()` or `::unknown()`, each with an optional note:

```php
namespace App\Redaction;

use Illuminate\Support\Facades\Http;
use Kirschbaum\Redactor\Verification\VerificationResult;
use Kirschbaum\Redactor\Verification\Verifier;
use Throwable;

class TwilioKeyVerifier implements Verifier
{
    public function name(): string { return 'twilio_key'; }

    public function host(): string { return 'api.twilio.com'; }

    public function supports(string $entity, string $rule): bool
    {
        return $entity === 'twilio_key';
    }

    public function verify(string $secret): VerificationResult
    {
        try {
            $response = Http::withToken($secret)->timeout(5)->get('https://api.twilio.com/2010-04-01/Accounts.json');

            return match (true) {
                $response->status() === 401 => VerificationResult::inactive('Twilio rejected the key (401).'),
                $response->successful() => VerificationResult::active('Twilio accepted the key; rotate it.'),
                default => VerificationResult::unknown(sprintf('Twilio returned %d.', $response->status())),
            };
        } catch (Throwable $e) {
            return VerificationResult::unknown('Could not reach Twilio: '.$e->getMessage());
        }
    }
}
```

The shipped verifiers are hard-wired into `SecretVerifier`; there is no registry for verifiers yet. To use your own, construct a `SecretVerifier` with the full list and give it to the scanner:

```php
use Kirschbaum\Redactor\Scanner\Scanner;
use Kirschbaum\Redactor\Verification\SecretVerifier;

$verifier = new SecretVerifier(
    allowed: ['twilio_key', 'github_token'],
    verifiers: [new TwilioKeyVerifier, new GitHubTokenVerifier],
);

$result = app(Scanner::class)->withVerifier($verifier)->scanFile($path, 'file_scan');
```

`SecretVerifier::fromConfig($settings, $verifiers)` applies the same three-gate rule to a custom list.

## Token Stores

`Tokenization\TokenStore` is where a token's original lives while the token is out in the world:

```php
namespace Kirschbaum\Redactor\Tokenization;

interface TokenStore
{
    public function put(string $token, string $value, string $entity, ?int $ttlSeconds = null): void;

    public function get(string $token): ?string;

    public function forget(string $token): void;
}
```

`get()` returns null for a token it does not know, and the detokenizer leaves such tokens alone. The shipped `CacheTokenStore` encrypts each value with the application's encrypter before writing it to the cache.

To use another store, bind it in a service provider's `register()`. The package resolves the store lazily the first time a `tokenize` operator runs, so the binding is picked up as long as it exists before then:

```php
use Kirschbaum\Redactor\Tokenization\TokenStore;

$this->app->singleton(TokenStore::class, fn () => new VaultTokenStore($this->app->make(Vault::class)));
```

## Macros

Both `Kirschbaum\Redactor\Redactor` and `Kirschbaum\Redactor\PendingRedaction` are `Macroable`, so an application can add its own methods to the facade and to the fluent builder:

```php
use Kirschbaum\Redactor\PendingRedaction;
use Kirschbaum\Redactor\Redactor;

Redactor::macro('forExport', fn (mixed $content) => $this->profile('observability')->withoutMarkers()->redact($content));

PendingRedaction::macro('strictly', fn () => $this->profile('strict'));
```

```php
Redactor::forExport($rows);
Redactor::profile(null)->strictly()->redact($data);
```

Both are also `Conditionable`, so `when()` and `unless()` are available on the redactor and on a pending redaction.
