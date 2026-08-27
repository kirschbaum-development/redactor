<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\Strategies\Contracts\PreservingStrategy;

/**
 * Declares a value safe by the name of the key holding it.
 *
 * Everything under a safe key is preserved, nested structures included. Only
 * list keys here whose contents cannot carry sensitive data by construction -
 * identifiers, timestamps, enumerations. A free-text field like "message" is
 * not safe just because it usually looks harmless.
 *
 * Supports the same '*' wildcards as BlockedKeysStrategy: '*_count', 'meta_*',
 * '*id*', 'user_*_id'. Matching is case-insensitive.
 */
class SafeKeysStrategy implements PreservingStrategy, RedactionStrategyInterface
{
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        // onError: false. A safe-key pattern that cannot be evaluated must not
        // declare the value safe - the failure mode here is a leak, not noise.
        return $context->config->safeKeyMatcher->matches($key, onError: false);
    }

    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        // Safe keys are never redacted - return original value
        return $value;
    }
}
