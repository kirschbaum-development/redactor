<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\Detection\Confidence;
use Kirschbaum\Redactor\Detection\Detection;
use Kirschbaum\Redactor\Operators\OperatorRegistry;
use Kirschbaum\Redactor\RedactionContext;

/**
 * Redacts a value because of the name of the key holding it.
 *
 * Supports exact names and '*' wildcards: '*token*', 'password*', '*_key',
 * 'user_*_token'. Matching is case-insensitive.
 *
 * The key is the entity. `operators.email` therefore applies to a value under
 * a key named `email` whether the key rule or the email pattern found it, so
 * "every email in this profile becomes a surrogate" holds without having to
 * know which strategy got there first.
 */
class BlockedKeysStrategy implements RedactionStrategyInterface
{
    /**
     * One certain score shared by every key-based detection.
     *
     * Built once: this runs for every blocked value in every payload, and a
     * fresh Confidence with a formatted reason per value was measurable.
     */
    private static ?Confidence $certain = null;

    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        // onError: true. An unevaluatable blocked-key pattern blocks the key.
        return $context->config->blockedKeyMatcher->matches($key, onError: true);
    }

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

        // Nullify keeps the key and drops the value, whatever the value was:
        // it is the operator for a typed field that must stay a field.
        if ($context->operatorSpecFor($detection)->name === OperatorRegistry::NULLIFY) {
            $context->recordDetection($detection);

            return null;
        }

        // Containers, booleans and nulls have no text an operator could act
        // on: masking an array or pseudonymising `true` means nothing. They
        // collapse to the replacement string as they always did.
        if (! $scalar) {
            $context->recordRedaction($key, 'blocked_key');

            return $context->config->replacement;
        }

        $context->recordDetection($detection);

        return $context->operate($detection);
    }
}
