<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Recognition;

/**
 * One span a recogniser believes names an entity, in character offsets.
 *
 * Character offsets, not bytes: every model and every sidecar reports
 * positions in the string as it tokenised it, and none of them count bytes.
 * The strategy converts, and verifies the conversion, before a span becomes
 * a Detection.
 */
final readonly class RecognizedSpan
{
    /**
     * Create a new recognized span instance.
     */
    public function __construct(
        /** The recogniser's own label: PERSON, LOCATION, ORGANIZATION. */
        public string $entity,
        /** Character offset of the first character. */
        public int $start,
        /** Character offset one past the last character. */
        public int $end,
        /** 0.0-1.0 as the recogniser reported it. */
        public float $score,
    ) {}
}
