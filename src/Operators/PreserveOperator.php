<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators;

use Kirschbaum\Redactor\Detection\Detection;

/**
 * Leave the value exactly as it was.
 *
 * Not a no-op in practice: it lets a scan profile detect and report without
 * rewriting anything, and lets one path rule carve an exception out of a
 * broader rule without disabling it.
 */
final class PreserveOperator implements Operator
{
    public function apply(Detection $detection, OperatorContext $context): string
    {
        return $detection->value;
    }

    public function isPreserving(): bool
    {
        return true;
    }
}
