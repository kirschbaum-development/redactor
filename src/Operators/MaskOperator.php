<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators;

use Kirschbaum\Redactor\Detection\Detection;

/** Replace each character with a mask character, preserving length. */
final class MaskOperator implements Operator
{
    public function apply(Detection $detection, OperatorContext $context): string
    {
        $char = mb_substr($context->stringOption('mask_character', '*'), 0, 1);

        return str_repeat($char, max(1, mb_strlen($detection->value)));
    }

    public function isPreserving(): bool
    {
        return false;
    }
}
