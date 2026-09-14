<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\Detection\Confidence;
use Kirschbaum\Redactor\Detection\Detection;
use Kirschbaum\Redactor\Detection\Detector;
use Kirschbaum\Redactor\Detection\KeywordContext;
use Kirschbaum\Redactor\Recognition\BatchRecognizer;
use Kirschbaum\Redactor\Recognition\CircuitBreaker;
use Kirschbaum\Redactor\Recognition\RecognizedSpan;
use Kirschbaum\Redactor\Recognition\Recognizer;
use Kirschbaum\Redactor\Recognition\Recognizers\PresidioRecognizer;
use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Strategies\Contracts\ConditionalStrategy;
use Kirschbaum\Redactor\Strategies\Contracts\DetectingStrategy;
use Kirschbaum\Redactor\Strategies\Contracts\PrimingStrategy;
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
 *
 * Before the walk, every prose value in the payload is gathered and sent in
 * one call, so a record with fifty free-text fields costs one round trip.
 */
class EntityRecognitionStrategy implements ConditionalStrategy, DetectingStrategy, Detector, PrimingStrategy, Strategy
{
    public const RULE = 'entity_recognition';

    /**
     * Recognise every prose value in the payload in one call, ahead of the walk.
     *
     * Values under safe or blocked keys are left out, since the walk will
     * preserve or replace them whole without reading them. A failure counts
     * once against the breaker and primes every value with nothing, so the
     * walk does not retry a dead recogniser once per value.
     */
    public function prime(mixed $content, RedactionContext $context): void
    {
        $settings = $context->config->recognition;

        if (($settings['batch'] ?? true) === false) {
            return;
        }

        $texts = [];
        $this->gather($content, '', $context, $texts);

        if ($texts === []) {
            return;
        }

        $recognizer = $this->recognizer($settings, $context);

        if (! $recognizer instanceof Recognizer || ! CircuitBreaker::allows($this->breakerKey($recognizer, $context))) {
            return;
        }

        $texts = array_values($texts);
        $spans = $this->askMany($recognizer, $texts, $context);

        $primed = [];

        foreach ($texts as $index => $text) {
            $primed[$text] = $spans[$index] ?? [];
        }

        $context->primeRecognition($primed);
    }

    /**
     * Ask the recogniser about every text, in one call if it can take a list.
     *
     * A throw becomes "rules only, this time" for every text in the batch.
     *
     * @param  array<int, string>  $texts
     * @return array<int, array<int, RecognizedSpan>>
     */
    private function askMany(Recognizer $recognizer, array $texts, RedactionContext $context): array
    {
        $settings = $context->config->recognition;
        $language = $this->string($settings, 'language', 'en');
        $entities = $this->labels($settings);
        $threshold = $this->float($settings, 'score_threshold', 0.6);

        try {
            if ($recognizer instanceof BatchRecognizer) {
                $spans = $recognizer->recognizeMany($texts, $language, $entities, $threshold);
            } else {
                $spans = [];

                foreach ($texts as $index => $text) {
                    $spans[$index] = $recognizer->recognize($text, $language, $entities, $threshold);
                }
            }
        } catch (Throwable $e) {
            $this->failed($recognizer, $context, $e);

            return [];
        }

        CircuitBreaker::recordSuccess($this->breakerKey($recognizer, $context));

        return $spans;
    }

    /**
     * Collect every prose value the walk would send, keyed by the text itself.
     *
     * Objects are opened the way the walk opens them, and the same depth and
     * cycle guards apply, so a payload the walk would stop on stops here too.
     *
     * @param  array<string, string>  $texts
     */
    private function gather(mixed $value, string $key, RedactionContext $context, array &$texts): void
    {
        if (is_string($value)) {
            if (! isset($texts[$value]) && $this->walkWouldRead($key, $context) && $this->shouldHandle($value, $key, $context)) {
                $texts[$value] = $value;
            }

            return;
        }

        if (! $this->walkWouldRead($key, $context)) {
            return;
        }

        if (is_array($value)) {
            $this->gatherFrom($value, $context, $texts);

            return;
        }

        // The object stays on the stack while its children are read, so a
        // toArray() that hands back its owner is entered once...
        if (is_object($value) && $context->enterObject($value)) {
            try {
                $opened = $this->open($value);

                if ($opened !== null) {
                    $this->gatherFrom($opened, $context, $texts);
                }
            } finally {
                $context->leaveObject($value);
            }
        }
    }

    /**
     * Collect prose from every child of the array, one level deeper.
     *
     * @param  array<array-key, mixed>  $array
     * @param  array<string, string>  $texts
     */
    private function gatherFrom(array $array, RedactionContext $context, array &$texts): void
    {
        if (! $context->enterDepth()) {
            return;
        }

        try {
            foreach ($array as $childKey => $child) {
                $this->gather($child, (string) $childKey, $context, $texts);
            }
        } finally {
            $context->leaveDepth();
        }
    }

    /**
     * Determine if the walk would read the value under the key rather than settle it by name.
     */
    private function walkWouldRead(string $key, RedactionContext $context): bool
    {
        if ($key === '') {
            return true;
        }

        return ! $context->config->safeKeyMatcher->matches($key, onError: false)
            && ! $context->config->blockedKeyMatcher->matches($key);
    }

    /**
     * Open an object into an array the way the walk does, or null when it is opaque.
     *
     * @return array<array-key, mixed>|null
     */
    private function open(object $object): ?array
    {
        if ($object instanceof Throwable || $object instanceof \DateTimeInterface || $object instanceof \DateTimeZone || $object instanceof \UnitEnum || $object instanceof \Closure) {
            return null;
        }

        try {
            if (method_exists($object, 'toArray')) {
                $array = $object->toArray();

                return is_array($array) ? $array : null;
            }

            $decoded = json_decode(json_encode($object, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);

            return is_array($decoded) ? $decoded : null;
        } catch (Throwable) {
            return null;
        }
    }

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

        if (! $recognizer instanceof Recognizer) {
            return [];
        }

        $threshold = $this->float($settings, 'score_threshold', 0.6);
        $spans = $context->primedRecognition($subject);

        if ($spans === null) {
            if (! CircuitBreaker::allows($this->breakerKey($recognizer, $context))) {
                return [];
            }

            $spans = $this->askOne($recognizer, $subject, $context);
        }

        return $this->toDetections($spans, $subject, $key, $recognizer->name(), $settings, $threshold);
    }

    /**
     * Ask the recogniser about one text.
     *
     * A throw becomes "rules only, this time" for that text.
     *
     * @return array<int, RecognizedSpan>
     */
    private function askOne(Recognizer $recognizer, string $subject, RedactionContext $context): array
    {
        $settings = $context->config->recognition;

        try {
            $spans = $recognizer->recognize(
                $subject,
                $this->string($settings, 'language', 'en'),
                $this->labels($settings),
                $this->float($settings, 'score_threshold', 0.6)
            );
        } catch (Throwable $e) {
            $this->failed($recognizer, $context, $e);

            return [];
        }

        CircuitBreaker::recordSuccess($this->breakerKey($recognizer, $context));

        return $spans;
    }

    /**
     * Count a failed call against the breaker and log it through the re-entrancy guard.
     */
    private function failed(Recognizer $recognizer, RedactionContext $context, Throwable $e): void
    {
        $settings = $context->config->recognition;

        $opened = CircuitBreaker::recordFailure(
            $this->breakerKey($recognizer, $context),
            $this->int($settings, 'failure_threshold', 3),
            $this->int($settings, 'cooldown', 60)
        );

        InternalLog::warning('Entity recognition failed; continuing with rules only', [
            'recognizer' => $recognizer->name(),
            'profile' => $context->config->profile,
            'reason' => $e->getMessage(),
            'breaker_opened' => $opened,
        ]);
    }

    /**
     * Get the breaker key for the recogniser under this profile.
     */
    private function breakerKey(Recognizer $recognizer, RedactionContext $context): string
    {
        return $recognizer->name().'|'.$context->config->profile;
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

        if (! $recognizer instanceof Recognizer) {
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

        return is_array($entities) ? array_values(array_filter($entities, is_string(...))) : [];
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
