<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\Detection\Confidence;
use Kirschbaum\Redactor\Detection\Detection;
use Kirschbaum\Redactor\Detection\Detector;
use Kirschbaum\Redactor\Detection\KeywordContext;
use Kirschbaum\Redactor\Patterns\PatternRule;
use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\Strategies\Contracts\DetectingStrategy;
use Kirschbaum\Redactor\Support\Pcre;

/**
 * Finds sensitive spans by pattern.
 *
 * The strategy detects, scores and locates; it does not rewrite. The context
 * collects what every detecting strategy reported about a value, resolves the
 * overlaps, and applies the configured operator to each surviving span in one
 * pass over the original string. That separation is what lets one profile
 * emit "[REDACTED]" and another emit a stable surrogate from exactly the same
 * detection - and what keeps that surrogate from being detected all over again
 * by whichever strategy runs next.
 */
class RegexPatternsStrategy implements DetectingStrategy, Detector, RedactionStrategyInterface
{
    /**
     * How much a passing checksum is worth.
     *
     * A Luhn-valid 16-digit run is a card with ~90% certainty; the same digits
     * failing Luhn are almost never one. This is the single strongest context
     * signal available, so it moves the score furthest.
     */
    private const VALIDATOR_BOOST = 0.75;

    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        return is_string($value) && $context->config->patterns !== [];
    }

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
     * Every span any rule accepts, in the order the rules are configured.
     *
     * Overlaps between rules are left in; the context resolves them.
     *
     * @return array<int, Detection>
     */
    public function detect(string $subject, string $key, RedactionContext $context): array
    {
        $detections = [];
        $lowered = null;
        $length = strlen($subject);

        foreach ($context->config->patternsByLength as [$rule, $priority]) {
            // The cheapest test first: a rule whose shortest possible match is
            // longer than the whole subject cannot match it, and neither can
            // any rule after it in this order. Most values in a log payload
            // are a few bytes and most credential rules need twenty or more,
            // so this retires most of the list before PCRE is involved.
            if ($rule->minLength > $length) {
                break;
            }

            // A rule that names keywords only runs on a subject containing one.
            // The email rule is the single most expensive thing in a clean-text
            // scan, and "does this contain an @" answers it in nanoseconds.
            //
            // Deliberately str_contains() per rule and not one combined regex:
            // a thirty-way alternation costs PCRE more than every rule it was
            // meant to save, since each rule's own pattern starts with a
            // literal and fails in a few nanoseconds.
            if ($rule->keywords !== []) {
                $lowered ??= strtolower($subject);

                if (! $this->containsAny($lowered, $rule->keywords)) {
                    continue;
                }
            }

            // Ask the cheap question inline. A capture-free preg_match() on a
            // subject that does not match costs a fraction of preg_match_all()
            // with offsets, and most rules do not match most values.
            $any = @preg_match($rule->pattern, $subject);

            if ($any === 0) {
                continue;
            }

            $found = $any === false || preg_last_error() !== PREG_NO_ERROR
                ? null
                : $this->detectRule($rule, $subject, $key, $priority);

            if ($found === null) {
                // The engine gave up partway through. Emitting a partially
                // inspected string would leak whatever it did not reach, so
                // the only safe report is "all of it".
                Pcre::matches($rule->pattern, $subject, onError: true, rule: $rule->name);

                return [Detection::failClosed(
                    $rule->entity(),
                    $rule->name,
                    $subject,
                    $key,
                    sprintf('pattern "%s" could not be evaluated; failing closed', $rule->name)
                )];
            }

            foreach ($found as $detection) {
                $detections[] = $detection;
            }
        }

        return $detections;
    }

    /**
     * Every span in the subject one rule accepts, in order.
     *
     * Returns null if the engine failed; an empty array means a clean subject.
     *
     * @return array<int, Detection>|null
     */
    private function detectRule(PatternRule $rule, string $subject, string $key, int $priority): ?array
    {
        $found = @preg_match_all($rule->pattern, $subject, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);

        if ($found === false || preg_last_error() !== PREG_NO_ERROR) {
            return null;
        }

        if ($matches === []) {
            return [];
        }

        $operator = $rule->hasExplicitOperator() ? $rule->operatorSpec() : null;
        $detections = [];

        foreach ($matches as $set) {
            $target = $rule->capture > 0 && isset($set[$rule->capture]) && $set[$rule->capture][1] >= 0
                ? $set[$rule->capture]
                : $set[0];

            [$text, $offset] = [(string) $target[0], (int) $target[1]];

            if ($text === '' || ! $rule->accepts($text)) {
                continue;
            }

            $confidence = $this->score($rule, $subject, $offset, $key);

            if ($rule->replacesWholeValue()) {
                // Legacy full mode: one match condemns the entire value. A
                // span the width of the subject swallows every other report.
                return [new Detection(
                    entity: $rule->entity(),
                    rule: $rule->name,
                    offset: 0,
                    value: $subject,
                    confidence: $confidence,
                    key: $key,
                    operator: $operator,
                    priority: $priority,
                )];
            }

            $detections[] = new Detection(
                entity: $rule->entity(),
                rule: $rule->name,
                offset: $offset,
                value: $text,
                confidence: $confidence,
                key: $key,
                operator: $operator,
                priority: $priority,
            );
        }

        return $detections;
    }

    /**
     * Score a match from the rule's base confidence plus what surrounds it.
     */
    private function score(PatternRule $rule, string $subject, int $offset, string $key): Confidence
    {
        $confidence = Confidence::of($rule->confidence, sprintf('pattern "%s" matched', $rule->name));

        if ($rule->validator !== null) {
            $confidence = $confidence->with(
                'validator',
                self::VALIDATOR_BOOST,
                sprintf('%s checksum passed', $rule->validator)
            );
        }

        return KeywordContext::boost($confidence, $subject, $offset, $key);
    }

    /**
     * @param  array<int, string>  $needles  already lowercased
     */
    private function containsAny(string $haystack, array $needles): bool
    {
        foreach ($needles as $needle) {
            if (str_contains($haystack, $needle)) {
                return true;
            }
        }

        return false;
    }
}
