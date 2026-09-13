<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Recognition\Recognizers;

use Illuminate\Support\Facades\Http;
use Kirschbaum\Redactor\Recognition\RecognizedSpan;
use Kirschbaum\Redactor\Recognition\Recognizer;
use RuntimeException;

/**
 * Talks to a Presidio analyzer over HTTP.
 *
 * Presidio's /analyze endpoint is the de facto contract for PII recognisers:
 * text in, a list of {entity_type, start, end, score} out. Anything that
 * speaks it - the reference analyzer with spaCy, the same with a transformer
 * recogniser, a FastAPI wrapper around a fine-tuned model - plugs in here
 * without a line of PHP.
 *
 * Runs wherever the profile says, which should never be the request path:
 * a model call costs milliseconds where the rule engine costs microseconds.
 */
class PresidioRecognizer implements Recognizer
{
    public function __construct(
        private readonly string $url = 'http://127.0.0.1:5002/analyze',
        private readonly float $timeout = 2.0,
    ) {}

    public function name(): string
    {
        return 'presidio';
    }

    public function withEndpoint(string $url, float $timeout): self
    {
        return new self($url, $timeout);
    }

    /**
     * @param  array<int, string>  $entities
     * @return array<int, RecognizedSpan>
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
