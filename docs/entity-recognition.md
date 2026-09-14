# Entity Recognition

- [Introduction](#introduction)
- [Enabling It](#enabling-it)
- [The Presidio Contract](#the-presidio-contract)
- [Gates](#gates)
- [Offsets](#offsets)
- [Batching](#batching)
- [The Circuit Breaker](#the-circuit-breaker)
- [Writing a Recognizer](#writing-a-recognizer)
- [When to Use It](#when-to-use-it)

## Introduction

Names, addresses and organisations are the PII no regex can express and no entropy measure can see. A named entity recogniser can find them, at a cost three orders of magnitude above the rule engine, so the package treats it as a gated extra rather than a default.

`EntityRecognitionStrategy` is listed in the shipped `default` profile and does nothing until `recognition.enabled` is true. When it is disabled the strategy is left out of the chain entirely, so it costs nothing.

## Enabling It

```php
'recognition' => [
    'enabled'         => true,
    'driver'          => 'presidio',
    'url'             => 'http://presidio:5002/analyze',
    'language'        => 'en',
    'entities'        => ['PERSON', 'LOCATION', 'ORGANIZATION'],
    'entity_map'      => ['PERSON' => 'person', 'LOCATION' => 'location', 'ORGANIZATION' => 'organization'],
    'score_threshold' => 0.6,
],

'operators' => [
    'person'   => 'surrogate',
    'location' => 'redact',
],
```

Every key is described in [Configuration](configuration.md#recognition). A profile that wants recognition must list `EntityRecognitionStrategy` in its `strategies`; of the shipped profiles only `default` does.

Recognised spans go through the same overlap resolution, confidence floor and operators as everything else. A `person` becomes a stable surrogate exactly the way an email does. Each finding has the rule name `entity_recognition` and, as its entity, whatever `entity_map` maps the recogniser's label to, or the label lowercased. Its confidence starts at the recogniser's own score and gains the [context boost](rules.md#confidence) beside a credential keyword.

## The Presidio Contract

The built-in driver speaks Presidio's `/analyze` contract: text in, a list of spans out.

Request:

```json
{
  "text": "Alice Smith lives in Berlin",
  "language": "en",
  "score_threshold": 0.6,
  "entities": ["PERSON", "LOCATION"]
}
```

`entities` is omitted when the profile's list is empty, which asks for everything the recogniser knows. Response:

```json
[
  {"entity_type": "PERSON", "start": 0, "end": 11, "score": 0.85},
  {"entity_type": "LOCATION", "start": 21, "end": 27, "score": 0.9}
]
```

Anything that speaks this works without a line of PHP: the reference Presidio analyzer, the same analyzer with a transformer recogniser, or a small wrapper around any fine-tuned model. Items with a missing or mistyped field are skipped. A non-2xx status or a non-list body counts as a failure.

The driver posts with `timeout` seconds to wait and a connect timeout of at most one second.

## Gates

Only a value that passes every gate is sent:

1. It is a string.
2. It is at least `min_length` and at most `max_length` bytes.
3. It has at least `min_words` whitespace-separated words.
4. It reads as prose: it does not start with `{`, `[` or `<`, and at least half its words are made of letters (with apostrophes, hyphens and ordinary punctuation allowed).

A JSON blob, a stack trace or a bare token is not something a model reads well, and its guesses would be the false positives the gate exists to prevent.

On the way back:

5. Only spans scoring at or above `score_threshold` are kept.
6. Only labels in `entities` are kept, when the list is not empty.
7. Only spans whose offsets line up with the value are kept. See [Offsets](#offsets).

## Offsets

A recogniser reports character offsets, because every model tokenises its own copy of the text and none of them count bytes. The strategy converts each span's `start` to a byte offset with `mb_substr()`, extracts the text between `start` and `end`, and checks that the bytes at that position in the value are exactly that text. A span that is empty, whose `end` is not past its `start`, that runs past the end of the value, or that does not line up is skipped with a warning, never guessed. The detection's offset is then a byte offset like every other finding's.

## Batching

A model call costs a round trip and almost nothing per extra byte, so a record with fifty free-text fields should cost one call, not fifty. Before the walk starts, the strategy gathers every value that passes the gates, leaves out anything under a safe or blocked key, since the walk will preserve or replace those without reading them, and sends the rest in one request. Identical texts are sent once. When the walk later reaches a value, it finds the spans already recognised and asks nothing.

The Presidio driver joins the texts with a blank line between them, sends them under one 60,000 character cap per request, and hands each span back to the text it fell in with offsets relative to that text. No entity spans a blank line, so a span that crosses the join is an artefact and is dropped. A recogniser of your own takes the list directly by implementing `BatchRecognizer`, and one that only implements `Recognizer` is asked once per text at the same point.

A batch that fails counts once against the breaker and primes every gathered value with nothing, so the walk does not retry a dead recogniser once per value. A value the walk truncates before the strategy sees it falls back to a single call for that value. Set `batch` to `false` to always ask per value.

## The Circuit Breaker

A sidecar that is down fails every call at the full timeout, so inside a log tap every line would wait seconds to be told nothing. A recogniser that throws is skipped and the output is rules-only for that value. After `failure_threshold` consecutive failures the breaker opens for `cooldown` seconds and the recogniser is not asked again until it closes; one success closes it.

Breaker state is per process and keyed by recogniser and profile. It is deliberately not shared through the cache, because a breaker that needed the cache to work would fail exactly when the cache does. Each failure and each unknown driver is logged through the package's re-entrancy guard, so the warning cannot loop back into the log tap that raised it.

## Writing a Recognizer

To plug in something that does not speak the Presidio contract, implement `Kirschbaum\Redactor\Recognition\Recognizer`:

```php
use Kirschbaum\Redactor\Recognition\RecognizedSpan;
use Kirschbaum\Redactor\Recognition\Recognizer;

class OnnxRecognizer implements Recognizer
{
    public function name(): string
    {
        return 'onnx';
    }

    /**
     * @param  array<int, string>  $entities  the recogniser's own labels; empty means all
     * @return array<int, RecognizedSpan>
     */
    public function recognize(string $text, string $language, array $entities, float $scoreThreshold): array
    {
        $spans = [];

        foreach ($this->model->predict($text) as $prediction) {
            $spans[] = new RecognizedSpan(
                entity: $prediction->label,   // 'PERSON'
                start: $prediction->start,    // character offset
                end: $prediction->end,        // character offset, exclusive
                score: $prediction->score,    // 0.0 to 1.0
            );
        }

        return $spans;
    }
}
```

A recogniser that can read a list in one call also implements `Kirschbaum\Redactor\Recognition\BatchRecognizer`, whose `recognizeMany()` takes an array of texts and returns spans per input index, with offsets relative to each text. See [Batching](#batching).

Register it, usually in a service provider's `boot()`, and select it by name:

```php
Redactor::registerRecognizer(new OnnxRecognizer);
```

```php
'recognition' => ['enabled' => true, 'driver' => 'onnx', /* ... */],
```

A recogniser reports; it never rewrites. It may throw when it cannot answer, and the strategy turns that into "rules only, this time" and counts it against the breaker. Return character offsets, not bytes.

## When to Use It

Use it on profiles that run from queues, exports and scans, where a model call's milliseconds are lost in the job's seconds and the payload is prose: support transcripts, free-text notes, exported records. Pair it with `surrogate` for people so an exported conversation stays readable and consistent.

Do not enable it on the request path or on a busy log channel. The rule engine costs microseconds per value; a recogniser costs milliseconds and a network round trip, per prose-shaped value, on every log line that carries one. The gates keep JSON and stack traces out, but a `message` field is prose by definition.

Do not rely on it for credentials. A model finds names; a pattern finds keys. The rules run either way.

The companion package `kirschbaum-development/redactor-onnx` removes the sidecar: the same gates, breaker and batching, with the model loaded once per worker. It suits queue workers, Octane and scans for the same reason a sidecar does, and a request that boots and exits for the same reason a sidecar does not.

To run a model inside the PHP process instead of a sidecar, install [kirschbaum-development/redactor-onnx](https://github.com/kirschbaum-development/redactor-onnx), which registers an `onnx` driver over TransformersPHP. It implements `BatchRecognizer`, so batching applies unchanged.
