# Testing

- [Introduction](#introduction)
- [Faking the Redactor](#faking-the-redactor)
    - [Assertions](#assertions)
    - [Inspecting Calls](#inspecting-calls)
- [Validating Profiles](#validating-profiles)
- [Rule Samples](#rule-samples)
- [Testing Surrogates](#testing-surrogates)
- [The Package's Own Tests](#the-packages-own-tests)

## Introduction

Redaction is a runtime promise, and a promise nobody tests is one that quietly stops being kept. The package gives you three ways to test it: a fake that records every call so a test can prove a secret never left, a command that resolves every profile so a bad one fails the deploy, and samples on rules so a regex edit that stops matching fails CI.

## Faking the Redactor

`Redactor::fake()` swaps the bound redactor for one that still redacts but remembers every call:

```php
use Kirschbaum\Redactor\Facades\Redactor;

$fake = Redactor::fake();

$this->postJson('/login', ['email' => 'bob@example.com', 'password' => 'hunter2']);

$fake->assertNeverEmitted('hunter2', 'bob@example.com');
$fake->assertRedacted('password');
$fake->assertFinding('email');
$fake->assertProfileUsed('strict');
```

The fake redacts for real, with the real configuration, so what it records is what production would have emitted. Install it before the code under test resolves the redactor. The log tap resolves it when the channel is first built, so `Redactor::fake()` belongs before the first `Log::` call in the test, and usually in `setUp()`.

`Redactor::fake()` returns the `RedactorFake` instance; the facade also forwards to it, so `Redactor::assertRedacted('password')` works.

### Assertions

| Assertion | Passes when |
| --- | --- |
| `assertNeverEmitted(string ...$secrets)` | None of the given strings appears in the output of any recorded call, whichever profile or path it took. Fails if no calls were recorded. |
| `assertRedacted(string $key)` | At least one call redacted something under the given key. |
| `assertNotRedacted(string $key)` | No call redacted anything under the given key. |
| `assertFinding(string $rule)` | At least one call produced a finding from the given rule, such as `email`, `blocked_key`, `shannon_entropy` or `known_secret`. |
| `assertSomethingRedacted()` | At least one call changed something. |
| `assertNothingRedacted()` | No call changed anything. |
| `assertProfileUsed(string $profile)` | At least one call ran with the given profile name. A call with no profile counts as `default`. |
| `assertCalled(int $times)` | Exactly that many calls were recorded. |
| `assertNotCalled()` | No calls were recorded. |

`assertNeverEmitted()` is the strongest thing a test can say about redaction: not "this key was handled" but "this secret did not get out", across every call. Output is compared as a string; arrays are JSON-encoded first.

### Inspecting Calls

```php
$fake->recorded();  // every call, oldest first: ['profile' => ?string, 'input' => mixed, 'result' => RedactionResult]
$fake->forget();    // clear the recording
```

Each recorded result is the `RedactionResult` the call returned, with its `findings`, so a test can make finer assertions than the built-in ones.

## Validating Profiles

```bash
php artisan redactor:validate
```

For every configured profile the command:

1. Resolves the profile, which throws on any invalid value with the config path in the message.
2. Reports any key listed in both `safe_keys` and `blocked_keys`. `SafeKeysStrategy` runs first, so such a key is silently never redacted.
3. Reports any entry in `strategies` that is neither a class implementing `Strategy` nor a registered custom strategy name.
4. Runs every rule's `samples` and `counter_samples` through the real detection path.

Output is one line per profile with `OK` or the error, and the command exits 1 if any profile fails. Run it in CI and at deploy time; a broken profile otherwise throws at log time, where it is replaced rather than emitted.

The same check is available in code as `Redactor::validateProfiles()`, which returns `profile => error message` for the broken ones.

## Rule Samples

Every rule can carry the texts it must detect and the texts it must leave alone:

```php
'order_ref' => [
    'pattern'         => '/\bORD-\d{6}\b/',
    'samples'         => ['ref ORD-123456'],
    'counter_samples' => ['ORD-12', 'ORDER-123456'],
],
```

`redactor:validate` checks each sample with the rule's keywords, minimum length, validator and allow lists applied, and names the rule and the sample that failed:

```
rule "order_ref" does not detect its sample "ref ORD-12"
rule "digits" detects its counter-sample "started at 1694600000"
```

A sample is checked against the rule that carries it, so another rule matching the same text neither passes nor fails it. Every shipped rule carries both, which is how the package's own test suite proves the shipped patterns still catch what they were written for.

## Testing Surrogates

Surrogates are only stable for a given key, so a test that asserts a specific surrogate needs a known one:

```php
config()->set('redactor.pseudonymization.key', 'a-test-pseudonymization-key-of-sufficient-length');

expect(Redactor::redact('alice@customer.com', 'observability'))
    ->toBe(Redactor::redact('alice@customer.com', 'observability'));
```

Most tests need only stability, which the example above asserts without hard-coding a surrogate. Without a key, and with `APP_KEY` empty in the test environment, the pseudonymising operators fall back to `[REDACTED]`.

## The Package's Own Tests

If you contribute to the package, the suite is Pest on Orchestra Testbench:

```bash
composer test           # full suite, in parallel
composer test-coverage  # with the 100% coverage floor enforced
composer lint           # Pint, Rector, PHPStan (level 10, no baseline)
composer rector:check   # what Rector would change, without changing it
composer mutate         # mutation testing (Pest); local only, not run in CI
composer preflight      # everything CI runs
```

Coverage and mutation testing need a coverage driver (pcov or Xdebug) loaded in the CLI; without one Pest reports no coverage and generates no mutations. Both scripts raise the memory limit, which the coverage report needs.

Conventions worth knowing:

- Tests live under `tests/Feature`, `tests/Unit` and `tests/Performance`, all bound to `Tests\TestCase`, which registers the service provider and calls `Http::preventingStrayRequests()` so no test can reach a real provider or recogniser.
- `testPseudonymizationKey()` in `tests/Pest.php` is the fixed key every suite uses for surrogate assertions.
- `runningWithCoverage()` lets timing-sensitive tests skip themselves under instrumentation, which flattens the difference between a fast and a slow implementation.
- Every redaction threshold has a boundary test at its edge, since on a redactor an off-by-one is the difference between catching a secret and emitting it.
- The pre-commit hook runs the same checks as `composer preflight`; `composer install` wires it up through `core.hooksPath`.
