<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators;

use Kirschbaum\Redactor\Detection\Detection;

/**
 * Replaces the span with the profile's replacement string.
 */
class RedactOperator implements Operator
{
    /**
     * Replace the span with the replacement string.
     */
    public function apply(Detection $detection, OperatorContext $context): string
    {
        return $context->replacement;
    }

    /**
     * Determine if the operator leaves the value as it found it.
     */
    public function isPreserving(): bool
    {
        return false;
    }
}
