<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Detection;

/**
 * One reason a detection is more or less likely to be real.
 *
 * Confidence is kept as a list of named contributions rather than a single
 * opaque float so a finding can explain itself, since a score nobody can
 * account for is a score nobody will tune.
 */
final readonly class Signal
{
    public function __construct(
        public string $name,
        public float $delta,
        public string $reason,
    ) {}

    /**
     * Describe the signal as a single line.
     */
    public function describe(): string
    {
        return sprintf('%s %+.2f (%s)', $this->name, $this->delta, $this->reason);
    }
}
