<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies\Contracts;

use Kirschbaum\Redactor\RedactionContext;

/**
 * A strategy that sees the whole payload once before the walk begins.
 *
 * The walk hands a strategy one value at a time, which is the wrong shape for
 * anything that pays per call rather than per byte. A priming strategy gets
 * the entire payload first, does its expensive work in one go, and leaves
 * what it learned on the context for its per-value handle() to pick up.
 */
interface PrimingStrategy extends Strategy
{
    /**
     * Look at the whole payload before any value is handled.
     */
    public function prime(mixed $content, RedactionContext $context): void;
}
