<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators;

use Kirschbaum\Redactor\Detection\Detection;

/**
 * Replaces each character with a mask character, preserving length.
 */
class MaskOperator implements Operator
{
    /**
     * Replace every character of the span with the mask character.
     */
    public function apply(Detection $detection, OperatorContext $context): string
    {
        $char = mb_substr($context->stringOption('mask_character', '*'), 0, 1);

        return str_repeat($char, max(1, mb_strlen($detection->value)));
    }

    /**
     * Determine if the operator leaves the value as it found it.
     */
    public function isPreserving(): bool
    {
        return false;
    }
}
