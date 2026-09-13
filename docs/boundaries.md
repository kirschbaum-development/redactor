# Boundaries

- [Introduction](#introduction)
- [Log Channels](#log-channels)
    - [The Tap](#the-tap)
    - [The Formatter](#the-formatter)
    - [Opaque Objects](#opaque-objects)
    - [Long Strings and Large Objects](#long-strings-and-large-objects)
- [HTTP Responses](#http-responses)
- [Streams](#streams)
- [MCP Servers](#mcp-servers)
- [AI Agents](#ai-agents)
- [Exports, Jobs and Everything Else](#exports-jobs-and-everything-else)
- [Events](#events)

## Introduction

Data leaves an application through more doors than the log. Each one below has an adapter that applies a profile at the boundary, so the same rules hold wherever a value goes and the profile name is the only thing that changes.

| Boundary | Adapter | Profile chosen by |
| --- | --- | --- |
| Log channel | `Logging\RedactorTap` | the tap's argument |
| HTTP response | `redact` middleware | the middleware's argument |
| Streamed output | `Streaming\StreamRedactor` | the constructor |
| MCP server | `Mcp\RedactsResponses` | `redactionProfile()` |
| AI agent prompt | `Ai\RedactPrompt` | `RedactPrompt::using()` |
| Anything else | `Redactor::redact()` | the second argument |

Every adapter uses `redactSafely()`, so a failure replaces the content rather than letting it through or throwing.

## Log Channels

### The Tap

Add `RedactorTap` to any channel in `config/logging.php`:

```php
'single' => [
    'driver' => 'single',
    'path' => storage_path('logs/laravel.log'),
    'level' => env('LOG_LEVEL', 'debug'),
    'tap' => [Kirschbaum\Redactor\Logging\RedactorTap::class],
],

'audit' => [
    'driver' => 'daily',
    'path' => storage_path('logs/audit.log'),
    'tap' => [Kirschbaum\Redactor\Logging\RedactorTap::class.':strict'],
],
```

The tap pushes a `RedactorProcessor` onto the channel's Monolog logger. The processor redacts the record's message, context and extra, and then the channel's own formatter renders the result, so a channel writing JSON keeps writing JSON. Put the tap on a `stack` channel and every channel in the stack is covered.

Redaction inside the processor never throws. A profile name typo, an unreadable config value or a strategy that fails on unexpected input all fail closed: the message becomes `[REDACTED] (redaction failed)`, the context and extra become `['redaction' => '...']`, and the record is still written. The package's own diagnostics go through a re-entrancy guard, so a warning raised inside the log pipeline cannot re-enter the handler that triggered it.

Run `php artisan redactor:validate` at deploy time to find a broken profile before the first log line does.

### The Formatter

`RedactorFormatter` is a Monolog formatter that redacts and renders. It owns the output format, so prefer the tap unless a channel specifically wants a self-contained drop-in. It can wrap an inner formatter rather than replace it:

```php
use Kirschbaum\Redactor\Logging\RedactorFormatter;
use Monolog\Formatter\JsonFormatter;

$handler->setFormatter(new RedactorFormatter(new JsonFormatter));
```

Without an inner formatter it writes `[datetime] channel.LEVEL: message {context} {extra}`. `formatBatch()` renders every record, so batching handlers lose nothing.

`RedactorFormatterTap` installs `RedactorFormatter` on every formattable handler of a channel. It discards whatever formatter the handler had, so a channel writing JSON stops writing JSON the moment it is enabled. It is the successor of the 0.1.0 `CustomLogTap` and is kept for channels that relied on it; new channels should use `RedactorTap`.

### Opaque Objects

Throwables, `DateTimeInterface`, `DateTimeZone`, enums and closures pass through the walk untouched. A Throwable has no public properties and would encode to `{}`, so `['exception' => $e]` reaching the formatter as `[]` would lose the stack trace; a Carbon instance would be exploded into its `toArray()` components. Every logging formatter already knows how to render them.

Key rules still apply, since the strategy chain runs before the opacity check:

```php
Log::error('failed', ['exception' => $e, 'password' => 'x']);
// ['exception' => $e, 'password' => '[REDACTED]']

Log::info('state', ['secret' => SomeEnum::Value]);
// ['secret' => '[REDACTED]']
```

Other objects are walked. Anything with a `toArray()` method, a model or a collection, is walked through that; anything else is walked through its JSON encoding. An object that can be neither converted is handled according to `non_redactable_object_behavior`: `preserve` (default), `remove`, `redact` or `empty_array`.

### Long Strings and Large Objects

The values most often over `max_value_length` in a Laravel log are stack traces and request bodies, which is exactly what the reader needed, so the default keeps the head, scans it, and notes what was cut:

```
Stack trace: #0 /app/Http/... [REDACTED] (String truncated: 65536 characters, 5000 kept)
```

Set `large_string_behavior` to `redact` to replace the whole value instead. An array or object with more items than `max_object_size` becomes `['_large_object_redacted' => '[REDACTED] (Array with 250 items)']`. A subtree deeper than `max_depth` becomes `[REDACTED] (Max depth of 32 exceeded)`, and an object already on the recursion stack becomes `[REDACTED] (Circular reference to App\Models\User)`.

## HTTP Responses

Data that leaves through an API needs the same boundary as data that leaves through a log. The package registers a `redact` middleware alias that redacts a response before it is sent, with a profile per route:

```php
Route::get('/export', ExportController::class)->middleware('redact:observability');
Route::get('/me', MeController::class)->middleware('redact');
```

What happens depends on the response:

| Response | Treatment |
| --- | --- |
| `JsonResponse` | Redacted as data, so structure and types survive. |
| Any response whose `Content-Type` contains `json` | Decoded, redacted as data, re-encoded. Falls back to text if the body is not valid JSON. |
| `text/*`, `xml`, `javascript`, `x-www-form-urlencoded`, or no content type | Redacted as text. |
| `StreamedResponse` | The callback is wrapped in a `StreamRedactor`. See [Streams](#streams). |
| `BinaryFileResponse`, any other content type, empty body | Passed through. |

The profile's `_redacted` markers are never written into a response. Where a consumer has typed the field, use `nullify` so the field stays a field and keeps its type:

```php
'operators' => ['ssn' => 'nullify', 'age' => 'nullify'],
```

The middleware fails closed. A response that cannot be redacted becomes a JSON `500` with the body `{"message": "The response could not be redacted."}` and none of the original content. Run `redactor:validate` at deploy time so that never happens in production.

## Streams

A streamed response, server-sent events, a model's tokens, a file piped through, is redacted as it streams. The `redact` middleware wraps a `StreamedResponse` callback for you; for anything else, use `StreamRedactor` directly:

```php
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Streaming\StreamRedactor;

$stream = new StreamRedactor(app(Redactor::class), 'observability');

// An iterable of chunks: a generator, an array, a model's token stream
foreach ($stream->through($llm->tokens()) as $safe) {
    echo $safe;
}

// A callback that echoes, wrapped so what it echoes is redacted
$callback = $stream->wrap(fn () => $this->export($rows));

// The same, as a StreamedResponse
return $stream->response(fn () => $this->export($rows), 200, ['Content-Type' => 'text/csv']);
```

For full control, feed chunks yourself:

```php
echo $stream->push($chunk);  // returns whatever is now safe to emit, possibly ''
echo $stream->flush();       // once the stream has ended
```

Redacting each chunk on its own would miss every secret that straddles a boundary, and buffering the whole stream would defeat the point of streaming. So `StreamRedactor` holds back the most recent bytes until more arrive:

- The last `holdback` bytes (the third constructor argument, default 1024) are never emitted until more input pushes them out.
- The cut always falls on a line end. No shipped rule except the PEM block matches across a newline, so a line end is always safe.
- When a stream goes a whole hold-back window without a line end, the cut falls on a word boundary instead. With no boundary at all, an unbroken run is emitted once it has outlived a window.
- A PEM block that has opened but not closed is held whole, however many lines it spans.

The cost is latency in bytes, not time. Raise the hold-back for content whose secrets are longer than a screen line. `wrap()` and `response()` take a `$chunkSize` (default 4096) for the output buffer that feeds the redactor.

## MCP Servers

An MCP server hands data straight to a model. With Laravel's MCP package, one trait redacts everything the server returns:

```php
use Kirschbaum\Redactor\Mcp\RedactsResponses;
use Laravel\Mcp\Server;

class SupportServer extends Server
{
    use RedactsResponses;

    protected function redactionProfile(): ?string
    {
        return 'observability';  // null for the default profile
    }
}
```

The trait sits where the server builds its JSON-RPC responses, so it covers HTTP and stdio alike, and the server's own test helpers exercise it: `SupportServer::tool(LookupCustomer::class)->assertDontSee($email)` tests the redaction along with the tool.

What is redacted:

| Part of the response | Treatment |
| --- | --- |
| `result.content[].text` (tool results) | As text. |
| `result.content[].resource.text` (embedded resources) | As text. |
| `result.structuredContent` | As data, without markers. If it cannot be redacted it becomes `['redaction' => 'failed']`. |
| `result.contents[]` (resource reads) | As text. |
| `result.messages[].content` (prompt messages) | As text, whether a string or a content block. |
| `error.message` | As text. |
| `params.content` of a streamed notification | As tool output. |

What is not: the JSON-RPC envelope, ids, protocol fields, and any binary content such as an image's `data` or a `blob`, so the protocol stays valid and an image is not mistaken for a high-entropy secret.

Use a profile whose operators tokenise when the model needs to refer to a value the application will act on. See [Reversible Tokens](operators-and-pseudonymisation.md#reversible-tokens). `laravel/mcp` is a suggested dependency, not a required one.

## AI Agents

With Laravel's AI package, the `RedactPrompt` middleware redacts a prompt before the provider sees it and resolves tokens in the answer on the way back:

```php
use Kirschbaum\Redactor\Ai\RedactPrompt;
use Laravel\Ai\Contracts\Agent;
use Laravel\Ai\Contracts\HasMiddleware;
use Laravel\Ai\Promptable;

class SupportAgent implements Agent, HasMiddleware
{
    use Promptable;

    public function instructions(): string
    {
        return 'You answer support tickets.';
    }

    public function middleware(): array
    {
        return [RedactPrompt::using('ai')];
    }
}
```

`RedactPrompt::using(?string $profile, bool $detokenizeResponse = true)` takes the profile and whether to resolve tokens in the response text. With a profile whose operators tokenise, the model reasons about `tok_email_k4m9rp2xzq` and the application receives the real address back in the response. With a profile that redacts outright, the model never sees the value. Pass `detokenizeResponse: false` to keep tokens in the answer, for instance when the answer is going to be logged or shown rather than acted on.

The round trip is:

1. The prompt text is passed through `redactSafely()` with the profile.
2. The revised prompt goes to the provider.
3. When the response arrives, `Redactor::detokenize()` replaces every known token in its text.

`laravel/ai` is a suggested dependency, not a required one.

## Exports, Jobs and Everything Else

The same call covers everything else an application emits. Every path accepts a profile name, so the same value can be pseudonymised on one channel and removed on another:

```php
// A queued export, on a profile that pseudonymises
ExportRow::create(Redactor::redact($user->toArray(), 'observability'));

// A support transcript before it reaches a third party
$client->createTicket(Redactor::redact($conversation, 'strict'));

// An error reporter's outgoing payload, in whichever hook it offers
$reporter->beforeSend(fn (array $event) => Redactor::redactSafely($event, 'strict'));

// A debug endpoint
return response()->json(Redactor::redact($state, 'performance'));
```

Use `redactSafely()` inside someone else's error path. It never throws and fails closed, which is what a hook that runs while an error is already being reported needs.

## Events

Every redaction that changed something dispatches `Kirschbaum\Redactor\Events\RedactionPerformed`:

```php
use Kirschbaum\Redactor\Events\RedactionPerformed;

Event::listen(RedactionPerformed::class, function (RedactionPerformed $event) {
    $event->profile;       // 'default'
    $event->redactedKeys;  // ['password', 'email'], deduplicated
    $event->rules;         // ['blocked_key' => 2, 'email' => 1]
    $event->entities;      // ['password' => 1, 'email' => 2]
    $event->findings;      // 3
});
```

The event carries names and counts only, never a value, so a listener that writes to metrics or an audit trail cannot itself become the leak. A listener that throws never breaks the redaction; the failure is logged and the redacted value is returned as normal.

Set `REDACTOR_EVENTS=false`, or `redactor.events` to false, to switch dispatching off.
