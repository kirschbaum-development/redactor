<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators;

use Kirschbaum\Redactor\Detection\Detection;

/**
 * Keep the last few characters and mask the rest.
 *
 * The tail is what lets a human confirm they are looking at the right record -
 * "the card ending 4242" - without the value being usable.
 */
final class PartialOperator implements Operator
{
    public function apply(Detection $detection, OperatorContext $context): string
    {
        $keep = max(0, $context->intOption('keep', 4));
        $char = mb_substr($context->stringOption('mask_character', '*'), 0, 1);
        $length = mb_strlen($detection->value);

        if ($length <= $keep) {
            // Too short to reveal any of it without revealing all of it.
            return str_repeat($char, max(1, $length));
        }

        return str_repeat($char, $length - $keep).mb_substr($detection->value, -$keep);
    }

    public function isPreserving(): bool
    {
        return false;
    }
}
