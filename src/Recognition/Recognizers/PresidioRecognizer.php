<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Recognition\Recognizers;

use Illuminate\Support\Facades\Http;
use Kirschbaum\Redactor\Recognition\BatchRecognizer;
use Kirschbaum\Redactor\Recognition\RecognizedSpan;
use RuntimeException;

/**
 * Talks to a Presidio analyzer over HTTP.
 *
 * Presidio's /analyze endpoint is the de facto contract for PII recognisers:
 * text in, a list of {entity_type, start, end, score} out. Anything that
 * speaks it, from the reference analyzer to a wrapper around a fine-tuned
 * model, plugs in here without a line of PHP. It runs wherever the profile
 * says, which should never be the request path: a model call costs
 * milliseconds where the rule engine costs microseconds.
 */
class PresidioRecognizer implements BatchRecognizer
{
    /**
     * The separator between texts joined into one request.
     *
     * No entity spans a blank line, so a span that crosses one is an artefact
     * of the join and is dropped rather than split.
     */
    public const SEPARATOR = "\n\n";

    /**
     * The most characters sent in one request.
     */
    public const BATCH_CHARACTERS = 60000;

    /**
     * Create a new Presidio recognizer instance.
     */
    public function __construct(
        private readonly string $url = 'http://127.0.0.1:5002/analyze',
        private readonly float $timeout = 2.0,
    ) {}

    /**
     * Get the stable name used in config to select the recogniser.
     */
    public function name(): string
    {
        return 'presidio';
    }

    /**
     * Create a copy of the recogniser pointed at the given endpoint.
     */
    public function withEndpoint(string $url, float $timeout): self
    {
        return new self($url, $timeout);
    }

    /**
     * Recognise entities in many texts with as few requests as the size cap allows.
     *
     * Presidio's contract takes one text, so the texts are joined with a blank
     * line between them, sent together, and each span is handed back to the
     * text it fell in with its offsets made relative to that text.
     *
     * @param  array<int, string>  $texts
     * @param  array<int, string>  $entities
     * @return array<int, array<int, RecognizedSpan>>
     *
     * @throws RuntimeException
     */
    public function recognizeMany(array $texts, string $language, array $entities, float $scoreThreshold): array
    {
        $results = [];

        foreach ($this->chunk($texts) as $chunk) {
            $joined = implode(self::SEPARATOR, $chunk);
            $spans = $this->recognize($joined, $language, $entities, $scoreThreshold);

            foreach ($this->segments($chunk) as $index => [$start, $end]) {
                $results[$index] = [];

                foreach ($spans as $span) {
                    if ($span->start >= $start && $span->end <= $end) {
                        $results[$index][] = new RecognizedSpan($span->entity, $span->start - $start, $span->end - $start, $span->score);
                    }
                }
            }
        }

        return $results;
    }

    /**
     * Split the texts into request-sized groups, keeping their indexes.
     *
     * @param  array<int, string>  $texts
     * @return array<int, array<int, string>>
     */
    private function chunk(array $texts): array
    {
        $chunks = [];
        $current = [];
        $length = 0;
        $separator = mb_strlen(self::SEPARATOR, 'UTF-8');

        foreach ($texts as $index => $text) {
            $characters = mb_strlen($text, 'UTF-8');

            if ($current !== [] && $length + $separator + $characters > self::BATCH_CHARACTERS) {
                $chunks[] = $current;
                $current = [];
                $length = 0;
            }

            $current[$index] = $text;
            $length += ($length === 0 ? 0 : $separator) + $characters;
        }

        if ($current !== []) {
            $chunks[] = $current;
        }

        return $chunks;
    }

    /**
     * Get the character range each text occupies once joined.
     *
     * @param  array<int, string>  $chunk
     * @return array<int, array{int, int}>
     */
    private function segments(array $chunk): array
    {
        $segments = [];
        $position = 0;
        $separator = mb_strlen(self::SEPARATOR, 'UTF-8');

        foreach ($chunk as $index => $text) {
            $characters = mb_strlen($text, 'UTF-8');
            $segments[$index] = [$position, $position + $characters];
            $position += $characters + $separator;
        }

        return $segments;
    }

    /**
     * Recognise entities in the given text using the Presidio analyzer.
     *
     * @param  array<int, string>  $entities
     * @return array<int, RecognizedSpan>
     *
     * @throws RuntimeException
     */
    public function recognize(string $text, string $language, array $entities, float $scoreThreshold): array
    {
        $payload = [
            'text' => $text,
            'language' => $language,
            'score_threshold' => $scoreThreshold,
        ];

        if ($entities !== []) {
            $payload['entities'] = array_values($entities);
        }

        $response = Http::timeout($this->timeout)
            ->connectTimeout(min(1.0, $this->timeout))
            ->acceptJson()
            ->post($this->url, $payload);

        if (! $response->successful()) {
            throw new RuntimeException(sprintf('Presidio returned %d.', $response->status()));
        }

        $decoded = $response->json();

        if (! is_array($decoded)) {
            throw new RuntimeException('Presidio returned a non-list body.');
        }

        $spans = [];

        foreach ($decoded as $item) {
            if (! is_array($item)) {
                continue;
            }

            $entity = $item['entity_type'] ?? null;
            $start = $item['start'] ?? null;
            $end = $item['end'] ?? null;
            $score = $item['score'] ?? null;

            if (! is_string($entity) || ! is_int($start) || ! is_int($end) || ! is_numeric($score)) {
                continue;
            }

            $spans[] = new RecognizedSpan($entity, $start, $end, (float) $score);
        }

        return $spans;
    }
}
