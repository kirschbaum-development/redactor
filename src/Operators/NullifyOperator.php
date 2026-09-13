<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators;

use Kirschbaum\Redactor\Detection\Detection;

/**
 * Replaces the value with null, keeping the key and the shape of the record.
 *
 * `[REDACTED]` in an integer field breaks every consumer that typed it, and
 * `remove` breaks the ones that require the key. Null keeps both honest: the
 * field is there, it has no value, and nothing downstream has to special-case
 * a sentinel. Inside a string there is no null to write, so a span found by a
 * pattern is deleted, as `remove` would.
 */
class NullifyOperator implements Operator
{
    /**
     * Delete the span, since a string has no null to write.
     */
    public function apply(Detection $detection, OperatorContext $context): string
    {
        return '';
    }
}
