<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Detection;

/**
 * One reason a detection is more or less likely to be real.
 *
 * Confidence is kept as a list of named contributions rather than a single
 * opaque float so a finding can explain itself: "0.95 = shape 0.60, luhn +0.30,
 * keyword 'card' nearby +0.05". A score nobody can account for is a score
 * nobody will tune.
 */
final readonly class Signal
{
    public function __construct(
        public string $name,
        public float $delta,
        public string $reason,
    ) {}

    public function describe(): string
    {
        return sprintf('%s %+.2f (%s)', $this->name, $this->delta, $this->reason);
    }
}
