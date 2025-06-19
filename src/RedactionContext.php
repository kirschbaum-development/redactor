<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor;

class RedactionContext
{
    /** @var array<string> */
    private array $redactedKeys = [];

    /** @var array<string, float> */
    private array $entropyCache = [];

    public bool $wasRedacted = false;

    public function __construct(
        public readonly RedactorConfig $config
    ) {}

    /**
     * Add a key to the list of redacted keys.
     */
    public function addRedactedKey(string $key): void
    {
        $this->redactedKeys[] = $key;
        $this->wasRedacted = true;
    }

    /**
     * Get all redacted keys.
     *
     * @return array<string>
     */
    public function getRedactedKeys(): array
    {
        return array_unique($this->redactedKeys);
    }

    /**
     * Mark that redaction occurred.
     */
    public function markRedacted(): void
    {
        $this->wasRedacted = true;
    }

    /**
     * Check if any redaction occurred.
     */
    public function hasRedactions(): bool
    {
        return $this->wasRedacted;
    }

    /**
     * Get cached entropy for a string.
     */
    public function getCachedEntropy(string $string): ?float
    {
        return $this->entropyCache[$string] ?? null;
    }

    /**
     * Cache entropy calculation for a string.
     */
    public function cacheEntropy(string $string, float $entropy): void
    {
        $this->entropyCache[$string] = $entropy;
    }
}
