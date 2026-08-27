<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators;

use Kirschbaum\Redactor\Detection\Detection;

/** Replace the span with the profile's replacement string. */
final class RedactOperator implements Operator
{
    public function apply(Detection $detection, OperatorContext $context): string
    {
        return $context->replacement;
    }

    public function isPreserving(): bool
    {
        return false;
    }
}
