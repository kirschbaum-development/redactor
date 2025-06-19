<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Scanner;

class ScanResult
{
    /**
     * @param  array<int, array<string, mixed>>  $findings
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
}
