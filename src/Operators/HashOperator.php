<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators;

use Kirschbaum\Redactor\Detection\Detection;
use Kirschbaum\Redactor\Support\Pseudonymizer;

/**
 * Replaces the span with a stable keyed token.
 *
 *     alice@customer.com  ->  [email:k4m9rp2xzq]
 *
 * The same value always yields the same token, so records stay countable and
 * joinable, and the token is obviously not real data, which is what you want
 * where a format-preserving surrogate could be mistaken for the genuine value.
 */
class HashOperator implements Operator
{
    /**
     * Replace the span with a keyed token.
     */
    public function apply(Detection $detection, OperatorContext $context): string
    {
        $pseudonymizer = $context->pseudonymizer();

        if (! $pseudonymizer instanceof Pseudonymizer) {
            // No key configured, so fail closed to a plain redaction rather than emit anything derived from the original...
            return $context->replacement;
        }

        $length = max(4, min(64, $context->intOption('length', 10)));
        $token = $pseudonymizer->token($detection->entity, $detection->value, $length);

        return $context->boolOption('labelled', true)
            ? sprintf('[%s:%s]', $detection->entity, $token)
            : $token;
    }
}
