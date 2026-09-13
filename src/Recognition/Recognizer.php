<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Recognition;

/**
 * A named entity recogniser: something that reads prose and says where the
 * people, places and organisations are.
 *
 * Regexes cannot express a name and entropy cannot see one, so this is the
 * seam through which a model - in a sidecar, in another process, behind a
 * cloud API - reports what it found. A recogniser reports spans in character
 * offsets with a score; it never rewrites, and it may throw: the strategy
 * that calls it turns failures into "rules only, this time" and trips a
 * breaker so a dead sidecar is not asked again on every log line.
 */
interface Recognizer
{
    /**
     * A stable name, used in config to select it.
     */
    public function name(): string;

    /**
     * @param  array<int, string>  $entities  the recogniser's own labels to look for; empty means all
     * @return array<int, RecognizedSpan>
     *
     * @throws \Throwable when the recogniser could not answer
     */
    public function recognize(string $text, string $language, array $entities, float $scoreThreshold): array;
}
