<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

/**
 * The result of running a value through the strategy chain.
 *
 * Distinguishes "no strategy touched this" (null outcome) from "a strategy
 * handled it and returned an identical value", which value identity alone
 * cannot express.
 */
final readonly class StrategyOutcome
{
    public function __construct(
        public mixed $value,
        /** Declared safe by a PreservingStrategy rather than redacted. */
        public bool $preserved = false,
    ) {}
}
