<?php

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\RedactionContext;

interface RedactionStrategyInterface
{
    /**
     * Check if this strategy should handle the given key-value pair.
     */
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool;

    /**
     * Handle the redaction for the given key-value pair.
     */
    public function handle(mixed $value, string $key, RedactionContext $context): mixed;
}
