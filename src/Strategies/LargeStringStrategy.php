<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\Strategies\Contracts\ChainableStrategy;
use Kirschbaum\Redactor\Strategies\Contracts\Strategy;

/**
 * Bounds the work done on a very long string.
 *
 * max_value_length exists so a pathological value, a multi-megabyte blob or a
 * base64 image, cannot make one log line cost seconds. Replacing the whole
 * value threw away the thing most often over the limit in a Laravel log, a
 * stack trace or a request body, so the default keeps the head, marks what was
 * cut, and hands the head on so a secret in it is still found.
 * `large_string_behavior: redact` restores the wholesale replacement.
 */
class LargeStringStrategy implements ChainableStrategy, Strategy
{
    /**
     * Determine if the string exceeds the profile's maximum length.
     */
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        return is_string($value)
            && $context->config->maxValueLength !== null
            && strlen($value) > $context->config->maxValueLength;
    }

    /**
     * Truncate or replace the string according to the profile.
     */
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

        // mb_strcut never splits a multibyte sequence, so the head stays valid UTF-8 for the strategies that scan it next...
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
