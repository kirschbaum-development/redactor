<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\Detection\Confidence;
use Kirschbaum\Redactor\Detection\Detection;
use Kirschbaum\Redactor\Detection\Detector;
use Kirschbaum\Redactor\Detection\KeywordContext;
use Kirschbaum\Redactor\Recognition\CircuitBreaker;
use Kirschbaum\Redactor\Recognition\RecognizedSpan;
use Kirschbaum\Redactor\Recognition\Recognizer;
use Kirschbaum\Redactor\Recognition\Recognizers\PresidioRecognizer;
use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Strategies\Contracts\ConditionalStrategy;
use Kirschbaum\Redactor\Strategies\Contracts\DetectingStrategy;
use Kirschbaum\Redactor\Strategies\Contracts\Strategy;
use Kirschbaum\Redactor\Support\InternalLog;
use Throwable;

/**
 * Asks a named entity recogniser about free text.
 *
 * Names, addresses and organisations are the PII no regex can express and no
 * entropy measure can see. A model can find them at a cost three orders of
 * magnitude above the rule engine, so this runs only when the profile enables
 * it, only on prose within a length window, and never belongs on the request
 * path. Spans are verified against the subject before they become detections,
 * and a failing recogniser trips a breaker and leaves the output rules-only.
 */
class EntityRecognitionStrategy implements ConditionalStrategy, DetectingStrategy, Detector, Strategy
{
    public const RULE = 'entity_recognition';

    /**
     * Determine if the profile enables entity recognition.
     */
    public function appliesTo(RedactorConfig $config): bool
    {
        return ($config->recognition['enabled'] ?? false) === true;
    }

    /**
     * Determine if the value is prose the recogniser should read.
     */
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        if (! is_string($value)) {
            return false;
        }

        $settings = $context->config->recognition;

        if (($settings['enabled'] ?? false) !== true) {
            return false;
        }

        $length = strlen($value);

        if ($length < $this->int($settings, 'min_length', 20) || $length > $this->int($settings, 'max_length', 5000)) {
            return false;
        }

        return $this->looksLikeProse($value, $this->int($settings, 'min_words', 3));
    }

    /**
     * Collect every entity the recogniser finds in the value.
     */
    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        if (! is_string($value)) {
            return $value;
        }

        foreach ($this->detect($value, $key, $context) as $detection) {
            $context->collect($detection);
        }

        return $value;
    }

    /**
     * Get every entity the recogniser finds in the subject.
     *
     * @return array<int, Detection>
     */
    public function detect(string $subject, string $key, RedactionContext $context): array
    {
        $settings = $context->config->recognition;
        $recognizer = $this->recognizer($settings, $context);

        if ($recognizer === null) {
            return [];
        }

        $breakerKey = $recognizer->name().'|'.$context->config->profile;

        if (! CircuitBreaker::allows($breakerKey)) {
            return [];
        }

        $entities = $this->labels($settings);
        $threshold = $this->float($settings, 'score_threshold', 0.6);

        try {
            $spans = $recognizer->recognize(
                $subject,
                $this->string($settings, 'language', 'en'),
                $entities,
                $threshold
            );
        } catch (Throwable $e) {
            $opened = CircuitBreaker::recordFailure(
                $breakerKey,
                $this->int($settings, 'failure_threshold', 3),
                $this->int($settings, 'cooldown', 60)
            );

            InternalLog::warning('Entity recognition failed; continuing with rules only', [
                'recognizer' => $recognizer->name(),
                'profile' => $context->config->profile,
                'reason' => $e->getMessage(),
                'breaker_opened' => $opened,
            ]);

            return [];
        }

        CircuitBreaker::recordSuccess($breakerKey);

        return $this->toDetections($spans, $subject, $key, $recognizer->name(), $settings, $threshold);
    }

    /**
     * Convert recognised spans into detections, verifying every offset.
     *
     * @param  array<int, RecognizedSpan>  $spans
     * @param  array<string, mixed>  $settings
     * @return array<int, Detection>
     */
    private function toDetections(array $spans, string $subject, string $key, string $recognizer, array $settings, float $threshold): array
    {
        $map = $this->entityMap($settings);
        $wanted = $this->labels($settings);
        $characters = mb_strlen($subject, 'UTF-8');
        $detections = [];

        foreach ($spans as $span) {
            if ($span->score < $threshold) {
                continue;
            }

            if ($span->end <= $span->start || $span->start < 0 || $span->end > $characters) {
                $this->warnMisaligned($recognizer, $span);

                continue;
            }

            if ($wanted !== [] && ! in_array($span->entity, $wanted, true)) {
                continue;
            }

            $byteOffset = strlen(mb_substr($subject, 0, $span->start, 'UTF-8'));
            $value = mb_substr($subject, $span->start, $span->end - $span->start, 'UTF-8');

            // The recogniser tokenised its own copy of the text, so a span whose offsets
            // do not land on the same characters here is skipped rather than guessed at...
            if (trim($value) === '' || substr($subject, $byteOffset, strlen($value)) !== $value) {
                $this->warnMisaligned($recognizer, $span);

                continue;
            }

            $entity = $map[$span->entity] ?? strtolower($span->entity);

            $confidence = Confidence::of(
                $span->score,
                sprintf('recognised as %s by %s', $span->entity, $recognizer)
            );

            $detections[] = new Detection(
                entity: $entity,
                rule: self::RULE,
                offset: $byteOffset,
                value: $value,
                confidence: KeywordContext::boost($confidence, $subject, $byteOffset, $key),
                key: $key,
            );
        }

        return $detections;
    }

    /**
     * Log a span whose offsets do not align with the subject.
     */
    private function warnMisaligned(string $recognizer, RecognizedSpan $span): void
    {
        InternalLog::warning('Entity recognition returned a span that does not align with the subject; skipped', [
            'recognizer' => $recognizer,
            'entity' => $span->entity,
            'start' => $span->start,
            'end' => $span->end,
        ]);
    }

    /**
     * Resolve the configured recogniser, if it is registered.
     *
     * @param  array<string, mixed>  $settings
     */
    private function recognizer(array $settings, RedactionContext $context): ?Recognizer
    {
        $driver = $this->string($settings, 'driver', 'presidio');
        $recognizer = $context->recognizers()->get($driver);

        if ($recognizer === null) {
            InternalLog::warning('Unknown entity recogniser; continuing with rules only', [
                'driver' => $driver,
                'available' => $context->recognizers()->names(),
                'profile' => $context->config->profile,
            ]);

            return null;
        }

        if ($recognizer instanceof PresidioRecognizer && isset($settings['url']) && is_string($settings['url'])) {
            return $recognizer->withEndpoint($settings['url'], $this->float($settings, 'timeout', 2.0));
        }

        return $recognizer;
    }

    /**
     * Determine if a value reads like text a model was trained on.
     *
     * A JSON document, a stack trace or a single token does not; the model
     * would guess, and its guesses are the false positives this gate avoids.
     */
    protected function looksLikeProse(string $value, int $minWords): bool
    {
        $trimmed = ltrim($value);

        if ($trimmed === '' || $trimmed[0] === '{' || $trimmed[0] === '[' || $trimmed[0] === '<') {
            return false;
        }

        $words = preg_split('/\s+/', trim($value), -1, PREG_SPLIT_NO_EMPTY);

        if ($words === false || count($words) < max(1, $minWords)) {
            return false;
        }

        $wordy = 0;

        foreach ($words as $word) {
            if (preg_match('/^[\p{L}][\p{L}\p{M}\'’.,;:!?-]*$/u', $word) === 1) {
                $wordy++;
            }
        }

        return $wordy * 2 >= count($words);
    }

    /**
     * Get the entity labels the profile asks for.
     *
     * @param  array<string, mixed>  $settings
     * @return array<int, string>
     */
    private function labels(array $settings): array
    {
        $entities = $settings['entities'] ?? [];

        return is_array($entities) ? array_values(array_filter($entities, 'is_string')) : [];
    }

    /**
     * Get the map from recogniser labels to package entities.
     *
     * @param  array<string, mixed>  $settings
     * @return array<string, string>
     */
    private function entityMap(array $settings): array
    {
        $map = $settings['entity_map'] ?? [];

        if (! is_array($map)) {
            return [];
        }

        $out = [];

        foreach ($map as $label => $entity) {
            if (is_string($label) && is_string($entity) && $entity !== '') {
                $out[$label] = $entity;
            }
        }

        return $out;
    }

    /**
     * Get an integer setting, or the default.
     *
     * @param  array<string, mixed>  $settings
     */
    private function int(array $settings, string $key, int $default): int
    {
        $value = $settings[$key] ?? null;

        return is_numeric($value) ? (int) $value : $default;
    }

    /**
     * Get a float setting, or the default.
     *
     * @param  array<string, mixed>  $settings
     */
    private function float(array $settings, string $key, float $default): float
    {
        $value = $settings[$key] ?? null;

        return is_numeric($value) ? (float) $value : $default;
    }

    /**
     * Get a non-empty string setting, or the default.
     *
     * @param  array<string, mixed>  $settings
     */
    private function string(array $settings, string $key, string $default): string
    {
        $value = $settings[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : $default;
    }
}
