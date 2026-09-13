<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\Strategies\Contracts\PreservingStrategy;
use Kirschbaum\Redactor\Strategies\Contracts\Strategy;

/**
 * Declares a value safe by the name of the key holding it.
 *
 * Everything under a safe key is preserved, nested structures included, so only
 * list keys whose contents cannot carry sensitive data by construction:
 * identifiers, timestamps, enumerations. A free-text field like "message" is
 * not safe just because it usually looks harmless. Supports the same '*'
 * wildcards as BlockedKeysStrategy, compared case-insensitively.
 */
class SafeKeysStrategy implements PreservingStrategy, Strategy
{
    /**
     * Determine if the key is in the profile's safe list.
     */
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        // onError: false, since a safe-key pattern that cannot be evaluated must not declare the value safe...
        return $context->config->safeKeyMatcher->matches($key, onError: false);
    }

    /**
     * Return the value untouched.
     */
    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        return $value;
    }
}
