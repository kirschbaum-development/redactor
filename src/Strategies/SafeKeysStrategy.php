<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\RedactionContext;

class SafeKeysStrategy implements RedactionStrategyInterface
{
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        $keyLower = strtolower($key);

        return in_array($keyLower, $context->config->safeKeys, true);
    }

    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        // Safe keys are never redacted - return original value
        return $value;
    }
}
