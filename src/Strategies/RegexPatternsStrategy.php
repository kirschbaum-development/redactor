<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\Patterns\PatternRule;
use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\Strategies\Contracts\ChainableStrategy;
use Kirschbaum\Redactor\Support\Pcre;

/**
 * Redacts the sensitive spans inside a string rather than the whole string.
 *
 * "Order 123 for bob@example.com failed" becomes
 * "Order 123 for [REDACTED] failed", not "[REDACTED]".
 */
class RegexPatternsStrategy implements ChainableStrategy, RedactionStrategyInterface
{
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        if (! is_string($value) || $context->config->patterns === []) {
            return false;
        }

        foreach ($context->config->patterns as $rule) {
            if ($this->matchesWithValidation($rule, $value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the rule finds anything in the subject that also passes its
     * structural check.
     */
    private function matchesWithValidation(PatternRule $rule, string $subject): bool
    {
        // onError: true. If the engine could not evaluate the pattern we do
        // not know the value is clean, so it is treated as sensitive.
        if ($rule->validator === null) {
            return Pcre::matches($rule->pattern, $subject, onError: true, rule: $rule->name);
        }

        $found = @preg_match_all($rule->pattern, $subject, $all, PREG_SET_ORDER);

        if ($found === false) {
            return true;
        }

        foreach ($all as $set) {
            $candidate = $rule->capture > 0 && isset($set[$rule->capture]) && $set[$rule->capture] !== ''
                ? $set[$rule->capture]
                : $set[0];

            if ($rule->accepts((string) $candidate)) {
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

        $replacement = $context->config->replacement;
        $result = $value;

        foreach ($context->config->patterns as $rule) {
            $applied = $this->applyRule($rule, $result, $replacement, $context, $key);

            if ($applied === null) {
                // The engine failed partway through. Emitting a partially
                // substituted string would leak whatever it did not reach.
                $context->recordRedaction($key, $rule->name);

                return $replacement;
            }

            $result = $applied;
        }

        return $result;
    }

    /**
     * Apply one rule to the whole subject, or null if PCRE gave up.
     */
    private function applyRule(
        PatternRule $rule,
        string $subject,
        string $replacement,
        RedactionContext $context,
        string $key
    ): ?string {
        if ($rule->replacesWholeValue()) {
            if (! $this->matchesWithValidation($rule, $subject)) {
                return $subject;
            }

            $context->recordRedaction($key, $rule->name);

            return $replacement;
        }

        $matched = false;

        $result = Pcre::replaceCallback(
            $rule->pattern,
            function (array $matches) use ($rule, $replacement, &$matched): string {
                /** @var array<int|string, array{0: string, 1: int}> $matches */
                $rewritten = $rule->rewriteMatch($matches, $replacement);

                // A match the rule's validator rejected is left as it was, and
                // must not count as a redaction.
                if ($rewritten !== $matches[0][0]) {
                    $matched = true;
                }

                return $rewritten;
            },
            $subject,
            $rule->name,
            PREG_OFFSET_CAPTURE
        );

        if ($result === null) {
            return null;
        }

        if ($matched) {
            $context->recordRedaction($key, $rule->name);
        }

        return $result;
    }
}
