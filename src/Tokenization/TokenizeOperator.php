<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Tokenization;

use Kirschbaum\Redactor\Detection\Detection;
use Kirschbaum\Redactor\Operators\Operator;
use Kirschbaum\Redactor\Operators\OperatorContext;
use Kirschbaum\Redactor\Support\Pseudonymizer;

/**
 * Replaces the span with a token the application can exchange back.
 *
 *     alice@customer.com  ->  tok_email_k4m9rp2xzq
 *
 * The token is derived the way a surrogate is, keyed and stable, so it stays
 * joinable, and it is spelt to survive a language model: one word, no
 * punctuation a tokenizer would split on, an entity name a model can reason
 * about. The original goes into the token store, encrypted, for as long as
 * the store's TTL allows. Without a pseudonymization key there is no stable
 * token to make, so the span is redacted instead.
 */
class TokenizeOperator implements Operator
{
    public const PREFIX = 'tok';

    public const ID_LENGTH = 12;

    /**
     * Create a new tokenize operator instance.
     */
    public function __construct(
        private readonly TokenStore $store,
        private readonly string $prefix = self::PREFIX,
    ) {}

    /**
     * Replace the span with a token and store the original.
     */
    public function apply(Detection $detection, OperatorContext $context): string
    {
        $pseudonymizer = $context->pseudonymizer();

        if (! $pseudonymizer instanceof Pseudonymizer) {
            return $context->replacement;
        }

        $entity = preg_replace('/[^a-z0-9]+/', '_', strtolower($detection->entity)) ?? 'value';
        $entity = trim($entity, '_') ?: 'value';

        $token = sprintf('%s_%s_%s', $this->prefix, $entity, $pseudonymizer->token('tokenize:'.$detection->entity, $detection->value, self::ID_LENGTH));

        $ttl = $context->intOption('ttl', -1);

        $this->store->put($token, $detection->value, $detection->entity, $ttl < 0 ? null : $ttl);

        return $token;
    }

    /**
     * Determine if the operator leaves the value as it found it.
     */
    public function isPreserving(): bool
    {
        return false;
    }
}
