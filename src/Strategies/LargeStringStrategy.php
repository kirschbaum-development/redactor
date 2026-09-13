<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\Strategies\Contracts\ChainableStrategy;

/**
 * Bounds the work done on a very long string.
 *
 * max_value_length exists so that a pathological value - a multi-megabyte
 * blob, a base64 image - cannot make one log line cost seconds. The pre-1.0
 * behaviour replaced the whole value, which is safe but throws away the thing
 * most often over the limit in a Laravel log: a stack trace or a request body,
 * which is exactly what the reader needed.
 *
 * The default now keeps the head, marks what was cut, and hands the head on to
 * the rest of the chain so a secret in the part that survives is still found.
 * `large_string_behavior: redact` restores the old wholesale replacement.
 */
class LargeStringStrategy implements ChainableStrategy, RedactionStrategyInterface
{
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        return is_string($value)
            && $context->config->maxValueLength !== null
            && strlen($value) > $context->config->maxValueLength;
    }

    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        if (! is_string($value)) {
            $context->markRedacted();

            return $value;
        }

        $length = strlen($value);
        $replacement = $context->config->replacement;

        if ($context->config->largeStringBehavior === 'redact') {
            $context->recordRedaction($key, 'large_string', 0, $length);

            return sprintf('%s (String with %d characters)', $replacement, $length);
        }

        $limit = $context->config->maxValueLength ?? $length;

        // mb_strcut never splits a multibyte sequence, so the head is still
        // valid UTF-8 for the strategies that scan it next.
        $head = mb_strcut($value, 0, $limit, 'UTF-8');

        $context->recordRedaction($key, 'large_string', strlen($head), $length - strlen($head));

        return sprintf(
            '%s %s (String truncated: %d characters, %d kept)',
            $head,
            $replacement,
            $length,
            strlen($head)
        );
    }
}
