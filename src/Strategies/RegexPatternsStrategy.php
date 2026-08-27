<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\Detection\Confidence;
use Kirschbaum\Redactor\Detection\Detection;
use Kirschbaum\Redactor\Patterns\PatternRule;
use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\Strategies\Contracts\ChainableStrategy;
use Kirschbaum\Redactor\Support\Pcre;

/**
 * Finds sensitive spans by pattern and hands each one to an operator.
 *
 * The strategy no longer decides what replacement looks like. It detects, scores
 * and locates; the operator configured for that entity decides whether the span
 * is redacted, masked, pseudonymised or left alone. That separation is what lets
 * one profile emit "[REDACTED]" and another emit a stable surrogate from exactly
 * the same detection.
 */
class RegexPatternsStrategy implements ChainableStrategy, RedactionStrategyInterface
{
    /**
     * How much a passing checksum is worth.
     *
     * A Luhn-valid 16-digit run is a card with ~90% certainty; the same digits
     * failing Luhn are almost never one. This is the single strongest context
     * signal available, so it moves the score furthest.
     */
    private const VALIDATOR_BOOST = 0.75;

    /**
     * How much a nearby keyword is worth.
     *
     * "token=" beside a high-entropy string is corroboration, not proof - the
     * word appears in plenty of prose too - so it nudges rather than decides.
     */
    private const KEYWORD_BOOST = 0.25;

    private const KEYWORD_WINDOW = 40;

    /** @var array<int, string> */
    private const KEYWORDS = [
        'secret', 'token', 'password', 'passwd', 'apikey', 'api_key', 'api-key',
        'credential', 'private', 'auth', 'bearer', 'key', 'card', 'cvv', 'ssn',
    ];

    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        if (! is_string($value) || $context->config->patterns === []) {
            return false;
        }

        foreach ($context->config->patterns as $rule) {
            if ($this->detect($rule, $value, $key, $context) !== []) {
                return true;
            }
        }

        return false;
    }

    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        if (! is_string($value)) {
            return $value;
        }

        $result = $value;

        foreach ($context->config->patterns as $rule) {
            $applied = $this->applyRule($rule, $result, $key, $context);

            if ($applied === null) {
                // The engine failed partway through. Emitting a partially
                // substituted string would leak whatever it did not reach.
                $context->recordRedaction($key, $rule->name, 0, strlen($result));

                return $context->config->replacement;
            }

            $result = $applied;
        }

        return $result;
    }

    /**
     * Rewrite every accepted detection for one rule, right to left.
     *
     * Right to left because operators change length: splicing from the end
     * means earlier offsets stay valid without tracking a running delta.
     *
     * Returns null when PCRE gave up, so the caller can fail closed.
     */
    private function applyRule(PatternRule $rule, string $subject, string $key, RedactionContext $context): ?string
    {
        $detections = $this->detect($rule, $subject, $key, $context);

        if ($detections === null) {
            return null;
        }

        if ($detections === []) {
            return $subject;
        }

        if ($rule->replacesWholeValue()) {
            $first = $detections[0];
            $context->recordRedaction($key, $rule->name, $first->offset, $first->length(), $first->value);

            return $context->operate($first, $rule);
        }

        $result = $subject;

        foreach (array_reverse($detections) as $detection) {
            $replacement = $context->operate($detection, $rule);

            if ($replacement === $detection->value) {
                // A preserving operator: detected, deliberately left alone.
                continue;
            }

            $result = substr_replace($result, $replacement, $detection->offset, $detection->length());

            $context->recordRedaction($key, $rule->name, $detection->offset, $detection->length(), $detection->value);
        }

        return $result;
    }

    /**
     * Every span in the subject this rule accepts, in order.
     *
     * Returns null if the engine failed; an empty array means a clean subject.
     *
     * @return array<int, Detection>|null
     */
    private function detect(PatternRule $rule, string $subject, string $key, RedactionContext $context): ?array
    {
        $found = @preg_match_all($rule->pattern, $subject, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);

        if ($found === false || preg_last_error() !== PREG_NO_ERROR) {
            Pcre::matches($rule->pattern, $subject, onError: true, rule: $rule->name);

            return null;
        }

        $detections = [];

        foreach ($matches as $set) {
            $target = $rule->capture > 0 && isset($set[$rule->capture]) && $set[$rule->capture][1] >= 0
                ? $set[$rule->capture]
                : $set[0];

            [$text, $offset] = [(string) $target[0], (int) $target[1]];

            if ($text === '' || ! $rule->accepts($text)) {
                continue;
            }

            $detection = new Detection(
                entity: $rule->entity(),
                rule: $rule->name,
                offset: $offset,
                value: $text,
                confidence: $this->score($rule, $text, $subject, $offset, $key),
                key: $key,
            );

            if ($context->accepts($detection)) {
                $detections[] = $detection;
            }
        }

        return $detections;
    }

    /**
     * Score a match from the rule's base confidence plus what surrounds it.
     */
    private function score(PatternRule $rule, string $text, string $subject, int $offset, string $key): Confidence
    {
        $confidence = Confidence::of($rule->confidence, sprintf('pattern "%s" matched', $rule->name));

        if ($rule->validator !== null) {
            $confidence = $confidence->with(
                'validator',
                self::VALIDATOR_BOOST,
                sprintf('%s checksum passed', $rule->validator)
            );
        }

        if ($this->hasNearbyKeyword($subject, $offset) || $this->keyLooksSensitive($key)) {
            $confidence = $confidence->with(
                'context',
                self::KEYWORD_BOOST,
                'a credential keyword appears alongside the match'
            );
        }

        return $confidence;
    }

    /**
     * Whether a credential keyword sits just before the match.
     *
     * Only the text ahead of the match is considered: "token=<value>" is a
     * label for what follows, whereas a keyword after the match usually belongs
     * to the next field.
     */
    private function hasNearbyKeyword(string $subject, int $offset): bool
    {
        $start = max(0, $offset - self::KEYWORD_WINDOW);
        $window = strtolower(substr($subject, $start, $offset - $start));

        if ($window === '') {
            return false;
        }

        foreach (self::KEYWORDS as $keyword) {
            if (str_contains($window, $keyword)) {
                return true;
            }
        }

        return false;
    }

    private function keyLooksSensitive(string $key): bool
    {
        if ($key === '') {
            return false;
        }

        $lower = strtolower($key);

        foreach (self::KEYWORDS as $keyword) {
            if (str_contains($lower, $keyword)) {
                return true;
            }
        }

        return false;
    }
}
