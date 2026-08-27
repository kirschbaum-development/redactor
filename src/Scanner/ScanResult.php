<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Scanner;

class ScanResult
{
    /**
     * @param  array<int, ScanFinding>  $findings
     */
    public function __construct(
        public readonly string $path,
        public readonly array $findings = [],
        public readonly ?string $profile = null,
        public readonly bool $skipped = false,
        public readonly ?string $error = null,
    ) {}

    public function hasFindings(): bool
    {
        return count($this->findings) > 0;
    }

    /**
     * The same result with any baseline-accepted findings removed.
     *
     * @param  array<string, true>  $acceptedFingerprints
     */
    public function withoutBaseline(array $acceptedFingerprints): self
    {
        if ($acceptedFingerprints === [] || ! $this->hasFindings()) {
            return $this;
        }

        return new self(
            path: $this->path,
            findings: array_values(array_filter(
                $this->findings,
                fn (ScanFinding $finding) => ! isset($acceptedFingerprints[$finding->fingerprint])
            )),
            profile: $this->profile,
            skipped: $this->skipped,
            error: $this->error,
        );
    }
}
