# Redactor Documentation

Redactor removes sensitive data from anything a Laravel application emits: log records, HTTP responses, streams, MCP tool results, prompts sent to a language model, exports and jobs. Detection is a set of rules you configure per profile; what happens to a detected value is a separate, per-entity decision called an operator.

## Start Here

If you are new to the package, read the pages in this order:

1. [Getting Started](getting-started.md) installs the package, adds the log tap and runs your first redaction.
2. [Boundaries](boundaries.md) shows where data leaves an application and which adapter covers each exit.
3. [Configuration](configuration.md) is the reference for every key in `config/redactor.php`.

Everything else can be read as you need it.

## Pages

| Page | What it covers |
| --- | --- |
| [Getting Started](getting-started.md) | Installation, the Monolog tap, `redact()`, `inspect()`, the fluent builder, profiles and the five that ship. |
| [Configuration](configuration.md) | Every top-level and per-profile key with its type, default and environment variable; the shipped profiles compared. |
| [Rules](rules.md) | Pattern rules, validators, keywords, samples, dictionary rules, allow-lists, path rules, safe and blocked keys, known secrets, confidence and how detections are resolved. |
| [Operators and Pseudonymisation](operators-and-pseudonymisation.md) | Every operator with example output, precedence, surrogates, the key and salt, reversible tokens and `detokenize()`. |
| [Boundaries](boundaries.md) | Log channels, HTTP responses, streams, MCP servers, AI agents, exports and jobs, and the `RedactionPerformed` event. |
| [Scanning](scanning.md) | `redactor:scan` in full: paths, output formats, git modes, decoding, baselines, inline suppression, verification, the pre-commit hook and exit codes. |
| [Entity Recognition](entity-recognition.md) | Finding names, places and organisations in prose with a Presidio-compatible recogniser or the in-process `redactor-onnx` package, and when not to. |
| [Testing](testing.md) | `Redactor::fake()` and its assertions, `redactor:validate`, rule samples, and the package's own test conventions. |
| [Extending](extending.md) | Every contract, how to register each, a worked custom strategy and operator, and macros. |
| [Upgrading](upgrading.md) | Every renamed class and method from 0.1.0, every behaviour change, and what to do about each. |

## Conventions

Code samples assume the facade is imported:

```php
use Kirschbaum\Redactor\Facades\Redactor;
```

Configuration paths are written relative to the file, so `profiles.default.patterns` means `config('redactor.profiles.default.patterns')`.
