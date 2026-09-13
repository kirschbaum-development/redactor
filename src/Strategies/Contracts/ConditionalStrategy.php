<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies\Contracts;

use Kirschbaum\Redactor\RedactorConfig;

/**
 * Marks a strategy that can tell, from the profile alone, that it has nothing
 * to do.
 *
 * A strategy that would say no to every value still costs a method call per
 * value to say it. Leaving it out of the chain when the profile has switched
 * it off, or given it nothing to look for, removes that cost entirely - and
 * because the chain is rebuilt whenever the profile is, switching it back on
 * takes effect at once.
 */
interface ConditionalStrategy
{
    public function appliesTo(RedactorConfig $config): bool;
}
