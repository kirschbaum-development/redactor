<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Detection;

use Kirschbaum\Redactor\RedactionContext;

/**
 * Something that finds sensitive spans in a string.
 *
 * A detector reads; it never writes. It reports every span it believes is
 * sensitive, with an entity, a score and the offsets in the subject exactly
 * as it received it, and leaves the decisions - which overlapping report wins,
 * whether the score clears the profile's floor, what replaces the span - to
 * the context that collected it.
 *
 * That contract is the same for a regex, an entropy measure, and a named
 * entity recogniser running in another process. Each one only has to answer
 * "what did you see, and how sure are you".
 */
interface Detector
{
    /**
     * @return array<int, Detection> offsets relative to $subject as given
     */
    public function detect(string $subject, string $key, RedactionContext $context): array;
}
