<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators;

use Kirschbaum\Redactor\Detection\Detection;

/**
 * What to do with something that was detected.
 *
 * Detection answers "is this sensitive"; an operator answers "so what". They
 * are separate because the right answer differs by context for the very same
 * value: an email in an audit log wants a stable surrogate so the log stays
 * joinable, the same email in a support export wants deleting, and in a
 * secret scan it wants reporting and nothing else.
 */
interface Operator
{
    /**
     * Produce the text that replaces the detected span.
     */
    public function apply(Detection $detection, OperatorContext $context): string;

    /**
     * Determine if the operator leaves the value as it found it.
     *
     * This decides whether anything changed, which drives the redaction flag.
     */
    public function isPreserving(): bool;
}
