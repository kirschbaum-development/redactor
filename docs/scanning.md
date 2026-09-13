# Scanning

- [Introduction](#introduction)
- [Scanning Paths](#scanning-paths)
- [Profiles](#profiles)
- [Output Formats](#output-formats)
    - [Table](#table)
    - [JSON](#json)
    - [SARIF](#sarif)
    - [JUnit](#junit)
- [Failing the Build](#failing-the-build)
- [Confidence Filtering](#confidence-filtering)
- [Scanning Changes, Not Files](#scanning-changes-not-files)
- [Looking Through Encodings](#looking-through-encodings)
- [Baselines](#baselines)
    - [The Ruleset Fingerprint](#the-ruleset-fingerprint)
- [Suppressing a Finding in Place](#suppressing-a-finding-in-place)
- [Verifying Credentials](#verifying-credentials)
- [The Pre-Commit Hook and Workflow](#the-pre-commit-hook-and-workflow)
- [Exit Codes](#exit-codes)
- [Options Reference](#options-reference)

## Introduction

`redactor:scan` runs a profile over files instead of payloads and reports where it found something. It is the same detection engine, so a rule you tune for logs is the rule that scans your repository, and every finding's excerpt is taken from the *redacted* text, so reports can be shared without publishing the secrets they report.

```bash
php artisan redactor:scan
```

## Scanning Paths

Pass files or directories; the default is the application's base path:

```bash
php artisan redactor:scan path/to/file.txt
php artisan redactor:scan app/ config/
```

Directories are walked with these exclusions:

- Files matching `scan.exclude_patterns`, tested against the basename and the path relative to the scanned directory. A pattern ending in `/*` prunes the whole directory.
- Files larger than `scan.max_file_size` (10 MB by default).
- Binary files, when `scan.skip_binary` is true: a NUL byte in the first 8 KB, or content that is neither valid UTF-8 nor mostly printable.
- Files git already ignores, when `scan.respect_gitignore` is true.

A file you name explicitly is scanned even if a pattern would exclude it. A path that does not exist is warned about and skipped.

Each file is read as overlapping windows of lines (`scan.window_lines` and `scan.overlap_lines`, 512 and 4 by default), so memory stays flat whatever the file size. Windows overlap so a secret spanning a boundary, a PEM block or a wrapped connection string, is still found; the duplicate the overlap produces is dropped by rule, line and column.

## Profiles

The scanner uses `scan.profile`, which is `file_scan` unless you change it, or whatever `--profile` names:

```bash
php artisan redactor:scan --profile=strict app/
```

`file_scan` has no key-based strategies, since a file has no keys, and adds labelled rules such as `password_assignment` and `aws_secret_key` that only make sense in source and config files. See [Configuration](configuration.md#the-shipped-profiles-compared).

## Output Formats

### Table

The default. Findings, not files, ranked by severity so the certain ones are read first:

```
  Severity  Rule            Location              Excerpt
  HIGH      aws_access_key  app/config.env:3:19   AWS_ACCESS_KEY_ID=[REDACTED]
  MEDIUM    email           app/seed.php:12:24    'contact' => '[REDACTED]',
```

Severity comes from confidence: `HIGH` at 0.9 and above, or for findings with no score such as a known secret; `MEDIUM` at 0.6; `LOW` at 0.3; `VERY LOW` below that. A credential confirmed live by [verification](#verifying-credentials) is `LIVE`, above everything else. Pass `--summary-only` to print the totals without the table.

### JSON

```bash
php artisan redactor:scan --output=json
```

One object per scanned file, with `path`, `ruleset`, `status` (`clean`, `findings` or `skipped`), `findings_count`, `findings`, `profile` and `error`. Each finding carries `rule`, `entity`, `line`, `column`, `excerpt`, `confidence`, `severity`, `signals`, `verification`, `commit`, `encoding`, `profile` and `fingerprint`. Nothing in it is the secret.

### SARIF

```bash
php artisan redactor:scan --output=sarif > redactor.sarif
```

SARIF 2.1.0, which GitHub code scanning renders inline on the pull request:

```yaml
- run: php artisan redactor:scan --output=sarif > redactor.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: redactor.sarif
```

Severity maps onto SARIF levels so a low-confidence hit is a note rather than a merge blocker: `high` is `error`, `medium` is `warning`, anything else `note`. Each result carries the finding's fingerprint under `partialFingerprints`, its entity, confidence and signals under `properties`, and the redacted excerpt as the snippet. The ruleset fingerprint is recorded under the tool driver's properties.

### JUnit

```bash
php artisan redactor:scan --output=junit
```

JUnit XML for a CI dashboard that already renders test results: one test case per scanned file, one failure per finding, a skipped element for a file that could not be read. The excerpt is already redacted.

Every format other than `table` suppresses the progress lines, so the output can be piped as-is.

## Failing the Build

```bash
php artisan redactor:scan --bail
```

Exits 1 when any finding survives the baseline and the confidence floor. Without `--bail` the command exits 0 whatever it finds.

## Confidence Filtering

```bash
php artisan redactor:scan --min-confidence=0.8
```

Raises the bar without weakening any pattern. The value must be between 0 and 1 and is applied to the profile before scanning, so a low-scoring detection is never acted on rather than filtered out afterwards. Each finding reports its score, its severity and the signals behind it, so the threshold can be chosen on evidence. See [Confidence](rules.md#confidence).

## Scanning Changes, Not Files

A gate on commits cares about what is being added, not what was already there. Three modes scan only the lines a change adds, so a pre-existing finding never blocks a commit and a secret is caught on the line that introduces it:

```bash
php artisan redactor:scan --staged                   # what is about to be committed
php artisan redactor:scan --diff=origin/main         # what the working tree adds over a ref
php artisan redactor:scan --history                  # every line every commit ever added
php artisan redactor:scan --history=main..HEAD app/  # a range, and a pathspec
```

Findings are reported on their real line numbers in the new file. In history mode each finding names the commit that added it, as `abcd1234:path:line:column`, and a secret that a later commit removed is still found: it is still in the repository.

With a git mode, the `paths` argument is passed to git as a pathspec rather than walked as directories. `scan.exclude_patterns` still apply. The command must run inside a git repository, and a git failure is reported and exits 1.

The added lines of each change are scanned as one text, so a secret spanning two adjacent added lines is still found.

## Looking Through Encodings

A secret in a repository is often not written plainly. A credential URL in a JSON file reads `https:\/\/user:pass@host`, a key in a Kubernetes secret is base64, a token in a query string is percent-encoded. With `scan.decode` on (the default), the scanner decodes one layer deep and scans what comes out:

| Encoding | What is decoded |
| --- | --- |
| `json` | Lines with JSON string escapes (`\/`, `\"`, `\uXXXX` and the rest). |
| `url` | Percent-encoded runs. |
| `base64` | Tokens of 20 or more base64 characters that contain upper case, lower case and a digit or symbol, and decode to printable text. |

A finding inside an encoded span reports the encoding, is located at the span's position, and its excerpt is taken from the decoded, redacted text with the encoding as a prefix: `[base64] password=[REDACTED]`. Set `REDACTOR_SCAN_DECODE=false` to switch it off.

Redaction of live payloads never decodes. That is a cost on every log line for a case the scanner is the right place to catch.

## Baselines

A repository with test fixtures or a documented example key can never go green without a baseline, so record what you have accepted and let CI fail only on new findings:

```bash
php artisan redactor:scan --update-baseline   # writes .redactor-baseline.json and exits 0
php artisan redactor:scan --bail              # now fails only on new secrets
```

The baseline path is `scan.baseline`, `.redactor-baseline.json` in the base path by default, or whatever `--baseline` names. `--update-baseline` needs one or the other.

The file stores, for each accepted finding, a fingerprint plus the rule and path for a human reading the diff. The fingerprint is a hash of the rule, the path and the secret; the secret itself is never written, and because the line number is not part of it a finding stays accepted when the code around it moves. Only the fingerprint is matched. A baseline that cannot be parsed fails the command.

### The Ruleset Fingerprint

Every scan reports a short digest of the rules it ran: the patterns and their options, the entropy settings, the confidence floor and the key lists. It appears in JSON output, in SARIF under the tool's properties, and in the baseline it writes.

Two runs with the same fingerprint are comparable. A baseline generated under a different fingerprint is warned about, since what it accepted may no longer mean the same thing; review it, or run `--update-baseline`.

## Suppressing a Finding in Place

A fixture, a documented example, a sandbox credential: mark the line and the scanner skips it, with the reason next to the code rather than in a baseline file:

```php
$stripe = 'sk_test_4eC39HqLyjWDarjtT1zdp7dc'; // redactor:allow - Stripe's public test key
```

The marker is `redactor:allow`, anywhere on the same line. It suppresses every finding on that line.

## Verifying Credentials

A scan of a mature repository turns up hundreds of candidates: expired keys, examples in docs, fixtures, rotated credentials. A list that cannot separate the live ones from the dead is a list nobody triages. Verification asks each provider directly whether a detected credential still works.

It also sends real secrets to third parties, so nothing happens unless all three of these agree:

1. `scan.verification.enabled` is true, in the config file, reviewable in a diff.
2. The run passes `--verify`, a human decision per run.
3. The provider is listed under `scan.verification.verifiers`, which says who you are willing to tell.

```php
'verification' => [
    'enabled' => env('REDACTOR_SCAN_VERIFY', false),
    'verifiers' => ['github_token', 'stripe_key', 'slack_token'],
],
```

```bash
php artisan redactor:scan --verify
```

An empty `verifiers` list means none: enabling the feature and choosing who to trust with the secrets are separate decisions. Passing `--verify` with verification disabled or with an empty list fails the command with a message saying so. Before contacting anyone, the command names every host it will contact. Redaction itself can never trigger verification; only the scan command can, because nothing running unattended inside an application should be making outbound calls with secrets in them.

The shipped verifiers:

| Name | Host | Checks |
| --- | --- | --- |
| `github_token` | `api.github.com` | `GET /user`; 401 means dead. |
| `stripe_key` | `api.stripe.com` | `GET /v1/balance`, read-only; 401 means dead. |
| `slack_token` | `slack.com` | `POST /api/auth.test`; the `ok` field decides, since Slack answers 200 either way. |

Each result is `active`, `inactive` or `unknown`. A confirmed-live credential is ranked `LIVE` (critical) above everything else. A check that could not complete is `unknown` and stays `high`, not `low`: failing to verify is not evidence of safety. A verifier that throws degrades its finding to `unknown` rather than abandoning the scan. The secret never reaches a finding, so it cannot escape through JSON, SARIF or a baseline.

To add a verifier, see [Extending](extending.md#verifiers).

## The Pre-Commit Hook and Workflow

Publish the hook and the workflow:

```bash
php artisan vendor:publish --tag=redactor-ci
git config core.hooksPath .githooks
```

This writes two files:

- `.githooks/pre-commit` runs `php artisan redactor:scan --staged --bail` before every commit, so only the secret being committed now can fail it. Accept pre-existing findings into the baseline or mark them `redactor:allow`.
- `.github/workflows/redactor-scan.yml` runs on pull requests and on pushes to `main`. On a pull request it scans the branch's changes over its base (`--diff=origin/<base> --bail --output=sarif`); on `main` it scans the whole tree against the committed baseline. Either way it uploads the SARIF to GitHub code scanning, so findings render inline on the diff. It checks out with `fetch-depth: 0`, which the diff and history modes need.

## Exit Codes

| Code | When |
| --- | --- |
| `0` | The scan completed. With `--bail`, nothing was found beyond the baseline. `--update-baseline` wrote the file. |
| `1` | `--bail` and at least one finding. Also: an unknown `--output`, a `--min-confidence` outside 0 to 1, a baseline that could not be parsed, a profile that could not be resolved, `--verify` without verification enabled and a verifier listed, a git failure or a path outside a git repository in a git mode, `--update-baseline` without a path or that could not be written. |

## Options Reference

```
redactor:scan
    {paths?*}            Paths to scan (files or directories, defaults to base_path); with a git mode, a pathspec
    {--profile=file_scan} Redaction profile to use
    {--bail}             Exit with code 1 if findings are detected
    {--summary-only}     Do not display per-file results
    {--output=table}     Output format (table|json|sarif|junit)
    {--staged}           Scan only the lines staged for commit
    {--diff=}            Scan only the lines the working tree adds over this ref, e.g. origin/main
    {--history=}         Scan the lines added by every commit, optionally in a range like main..HEAD
    {--min-confidence=}  Ignore findings scoring below this (0-1)
    {--verify}           Check detected credentials against their providers (sends them off this machine)
    {--baseline=}        Path to a baseline file of accepted findings
    {--update-baseline}  Write the current findings to the baseline file and exit 0
```

`--staged`, `--diff` and `--history` are checked in that order; the first one present wins.
