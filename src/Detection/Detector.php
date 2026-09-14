<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Detection;

use Kirschbaum\Redactor\RedactionContext;

/**
 * Something that finds sensitive spans in a string.
 *
 * A detector reads; it never writes. It reports every span it believes is
 * sensitive, with an entity, a score and offsets in the subject exactly as
 * received, and leaves the decisions to the context that collected it. The
 * contract is the same for a regex, an entropy measure and a named entity
 * recognizer running in another process.
 */
interface Detector
{
    /**
     * Detect sensitive spans in the given subject.
     *
     * @return array<int, Detection> offsets relative to $subject as given
     */
    public function detect(string $subject, string $key, RedactionContext $context): array;
}
