<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators;

use Kirschbaum\Redactor\Detection\Detection;
use Kirschbaum\Redactor\Operators\Surrogates\SurrogateFactory;
use Kirschbaum\Redactor\Support\Pseudonymizer;

/**
 * Replaces the span with a stable fake of the same shape.
 *
 *     alice@customer.com   ->  u_7f3ac9@customer.com
 *     4111 1111 1111 1111  ->  4111 1193 7420 8846
 *     sk_live_4eC39HqLyj   ->  sk_live_9mB71TzKnQ
 *
 * This is what keeps a redacted log usable. "[REDACTED]" collapses every
 * distinct value into one, which destroys counts, joins and traces; a stable
 * surrogate preserves all three while leaking none of the original.
 */
class SurrogateOperator implements Operator
{
    /**
     * Create a new surrogate operator instance.
     */
    public function __construct(
        private readonly SurrogateFactory $surrogates = new SurrogateFactory,
    ) {}

    /**
     * Replace the span with a surrogate of the same shape.
     */
    public function apply(Detection $detection, OperatorContext $context): string
    {
        $pseudonymizer = $context->pseudonymizer();

        if (! $pseudonymizer instanceof Pseudonymizer) {
            // Without a key there is no stable mapping to produce, and an unstable one would look joinable and silently not be...
            return $context->replacement;
        }

        return $this->surrogates->generate(
            $detection->entity,
            $detection->value,
            $pseudonymizer->random($detection->entity, $detection->value),
            $context->options,
        );
    }
}
