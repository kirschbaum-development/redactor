<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Events;

/**
 * Something was redacted. What, by which rule, under which profile - never
 * the value.
 *
 * Listen to it to chart what leaks where: which rules fire most, which
 * profiles do the work, whether a deploy changed the shape of what is being
 * caught. It carries counts and names only, so a listener that writes to
 * metrics or to a log cannot itself become the leak.
 */
final readonly class RedactionPerformed
{
    /**
     * @param  array<int, string>  $redactedKeys  keys that were redacted, deduplicated
     * @param  array<string, int>  $rules  rule name => number of findings
     * @param  array<string, int>  $entities  entity => number of findings
     */
    public function __construct(
        public string $profile,
        public array $redactedKeys,
        public array $rules,
        public array $entities,
        public int $findings,
    ) {}
}
