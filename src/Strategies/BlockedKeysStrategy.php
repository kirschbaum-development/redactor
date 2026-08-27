<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\Support\KeyMatcher;

/**
 * Redacts a value because of the name of the key holding it.
 *
 * Supports exact names and '*' wildcards: '*token*', 'password*', '*_key',
 * 'user_*_token'. Matching is case-insensitive.
 */
class BlockedKeysStrategy implements RedactionStrategyInterface
{
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        // onError: true. An unevaluatable blocked-key pattern blocks the key.
        return KeyMatcher::for($context->config->blockedKeys)->matches($key, onError: true);
    }

    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        $context->recordRedaction($key, 'blocked_key');

        return $context->config->replacement;
    }
}
