<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\RedactionContext;

class BlockedKeysStrategy implements RedactionStrategyInterface
{
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        $keyLower = strtolower($key);

        foreach ($context->config->blockedKeys as $blockedKey) {
            // Check for wildcard patterns
            if ($this->matchesPattern($keyLower, $blockedKey)) {
                return true;
            }
        }

        return false;
    }

    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        $context->addRedactedKey($key);

        return $context->config->replacement;
    }

    /**
     * Check if a key matches a blocked key pattern.
     * Supports wildcard patterns using '*' as a wildcard character.
     */
    private function matchesPattern(string $key, string $pattern): bool
    {
        // If no wildcards, do exact match (case-insensitive)
        if (strpos($pattern, '*') === false) {
            return $key === strtolower($pattern);
        }

        // Convert wildcard pattern to regex
        // Escape the pattern first, then replace escaped wildcards
        $regexPattern = '/^'.str_replace('\\*', '.*', preg_quote($pattern, '/')).'$/i';

        return preg_match($regexPattern, $key) === 1;
    }
}
