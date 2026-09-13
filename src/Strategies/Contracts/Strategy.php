<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies\Contracts;

use Kirschbaum\Redactor\RedactionContext;

/**
 * One step of the chain a value passes through.
 */
interface Strategy
{
    /**
     * Determine if the strategy should handle the value under the given key.
     */
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool;

    /**
     * Handle the value and return what should stand in its place.
     */
    public function handle(mixed $value, string $key, RedactionContext $context): mixed;
}
