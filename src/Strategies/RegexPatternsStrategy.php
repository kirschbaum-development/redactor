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
            // onError: true. If the engine could not evaluate the pattern we do
            // not know the value is clean, so it is treated as sensitive.
            if (Pcre::matches($rule->pattern, $value, onError: true, rule: $rule->name)) {
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
            if (! Pcre::matches($rule->pattern, $subject, onError: true, rule: $rule->name)) {
                return $subject;
            }

            $context->recordRedaction($key, $rule->name);

            return $replacement;
        }

        $matched = false;

        $result = Pcre::replaceCallback(
            $rule->pattern,
            function (array $matches) use ($rule, $replacement, &$matched): string {
                $matched = true;

                /** @var array<int|string, array{0: string, 1: int}> $matches */
                return $rule->rewriteMatch($matches, $replacement);
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
