<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies\Contracts;

use Kirschbaum\Redactor\RedactorConfig;

/**
 * Marks a strategy that can tell, from the profile alone, that it has nothing to do.
 *
 * A strategy that would refuse every value still costs a method call per value
 * to refuse it. Leaving it out of the chain when the profile switches it off
 * removes that cost, and since the chain is rebuilt with the profile, switching
 * it back on takes effect at once.
 */
interface ConditionalStrategy
{
    /**
     * Determine if the strategy has anything to do under the given configuration.
     */
    public function appliesTo(RedactorConfig $config): bool;
}
