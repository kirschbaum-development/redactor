<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators;

use Kirschbaum\Redactor\Detection\Detection;

/** Delete the span entirely. */
final class RemoveOperator implements Operator
{
    public function apply(Detection $detection, OperatorContext $context): string
    {
        return '';
    }

    public function isPreserving(): bool
    {
        return false;
    }
}
