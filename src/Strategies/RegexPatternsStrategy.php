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
use Kirschbaum\Redactor\Strategies\Contracts\Strategy;
use Kirschbaum\Redactor\Support\Pcre;

/**
 * Finds sensitive spans by pattern.
 *
 * The strategy detects, scores and locates; it does not rewrite. The context
 * collects what every detecting strategy reported, resolves the overlaps, and
 * applies the configured operator to each surviving span in one pass over the
 * original string. That is what lets one profile emit "[REDACTED]" and another
 * a stable surrogate from the same detection, and what keeps the surrogate
 * from being detected again by whichever strategy runs next.
 */
class RegexPatternsStrategy implements DetectingStrategy, Detector, Strategy
{
    /**
     * The confidence boost a passing checksum is worth.
     *
     * A Luhn-valid 16-digit run is a card with ~90% certainty and the same
     * digits failing Luhn almost never are, so this is the strongest signal.
     */
    private const float VALIDATOR_BOOST = 0.75;

    /**
     * Determine if the value is a string and the profile has patterns.
     */
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        return is_string($value) && $context->config->patterns !== [];
    }

    /**
     * Collect every pattern match in the value.
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
     * Get every span any rule accepts, in the order the rules are configured.
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
            // A rule whose shortest possible match is longer than the subject cannot
            // match it, and neither can any rule after it in this length order...
            if ($rule->minLength > $length) {
                break;
            }

            // A rule that names keywords only runs on a subject containing one, checked
            // with str_contains() per rule since a thirty-way alternation costs PCRE
            // more than every rule it was meant to save...
            if ($rule->keywords !== []) {
                $lowered ??= strtolower($subject);

                if (! $this->containsAny($lowered, $rule->keywords)) {
                    continue;
                }
            }

            // A capture-free preg_match() on a non-matching subject costs a fraction of
            // preg_match_all() with offsets, and most rules do not match most values...
            $any = @preg_match($rule->pattern, $subject);

            if ($any === 0) {
                continue;
            }

            $found = $any === false || preg_last_error() !== PREG_NO_ERROR
                ? null
                : $this->detectRule($rule, $subject, $key, $priority);

            if ($found === null) {
                // The engine gave up partway through, and a partially inspected string
                // would leak whatever it did not reach, so report all of it...
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
     * Get every span in the subject one rule accepts, in order.
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
                // Legacy full mode condemns the entire value on one match, and a span
                // the width of the subject swallows every other report...
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
     * Determine if the haystack contains any of the given needles.
     *
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
