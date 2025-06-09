<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\RedactionContext;

class BlockedKeysStrategy implements RedactionStrategyInterface
{
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        $keyLower = strtolower($key);

        return in_array($keyLower, $context->config->blockedKeys, true);
    }

    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        $context->addRedactedKey($key);

        return $context->config->replacement;
    }
}
