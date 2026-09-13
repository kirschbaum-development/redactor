<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators;

use Kirschbaum\Redactor\Detection\Detection;

/**
 * Deletes the span entirely.
 */
class RemoveOperator implements Operator
{
    /**
     * Delete the span.
     */
    public function apply(Detection $detection, OperatorContext $context): string
    {
        return '';
    }
}
