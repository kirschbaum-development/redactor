<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\Detection\Confidence;
use Kirschbaum\Redactor\Detection\Detection;
use Kirschbaum\Redactor\Operators\OperatorRegistry;
use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\Strategies\Contracts\Strategy;

/**
 * Redacts a value because of the name of the key holding it.
 *
 * Supports exact names and '*' wildcards ('*token*', 'password*', '*_key',
 * 'user_*_token'), compared case-insensitively. The key is the entity, so
 * `operators.email` applies to a value under a key named `email` whether the
 * key rule or the email pattern found it first.
 */
class BlockedKeysStrategy implements Strategy
{
    /**
     * The certain score shared by every key-based detection.
     *
     * Built once: this runs for every blocked value in every payload, and a
     * fresh Confidence with a formatted reason per value was measurable.
     */
    private static ?Confidence $certain = null;

    /**
     * Determine if the key is in the profile's blocked list.
     */
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        // onError: true, since an unevaluatable blocked-key pattern blocks the key...
        return $context->config->blockedKeyMatcher->matches($key, onError: true);
    }

    /**
     * Redact the value under the blocked key.
     */
    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        $scalar = is_string($value) || is_int($value) || is_float($value);

        if ($scalar && $context->isAllowed((string) $value)) {
            return $value;
        }

        $detection = new Detection(
            entity: strtolower($key),
            rule: 'blocked_key',
            offset: 0,
            value: $scalar ? (string) $value : '',
            confidence: self::$certain ??= Confidence::of(Confidence::CERTAIN, 'the key is in blocked_keys'),
            key: $key,
        );

        // Nullify keeps the key and drops the value, since it is the operator for a typed field that must stay a field...
        if ($context->operatorSpecFor($detection)->name === OperatorRegistry::NULLIFY) {
            $context->recordDetection($detection);

            return null;
        }

        // Containers, booleans and nulls have no text an operator could act on, so they collapse to the replacement string...
        if (! $scalar) {
            $context->recordRedaction($key, 'blocked_key');

            return $context->config->replacement;
        }

        $context->recordDetection($detection);

        return $context->operate($detection);
    }
}
