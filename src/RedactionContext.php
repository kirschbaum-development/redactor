<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor;

class RedactionContext
{
    /** @var array<int, string> */
    private array $redactedKeys = [];

    /**
     * Objects currently on the recursion stack, used to break reference cycles.
     *
     * @var \SplObjectStorage<object, null>
     */
    private \SplObjectStorage $activeObjects;

    private int $depth = 0;

    /** @var array<string, float> */
    private array $entropyCache = [];

    public bool $wasRedacted = false;

    public function __construct(
        public readonly RedactorConfig $config
    ) {
        /** @var \SplObjectStorage<object, null> $storage */
        $storage = new \SplObjectStorage;
        $this->activeObjects = $storage;
    }

    /**
     * Enter one level of nesting. Returns false when the configured max depth
     * would be exceeded, in which case the caller must not recurse.
     */
    public function enterDepth(): bool
    {
        if ($this->depth >= $this->config->maxDepth) {
            return false;
        }

        $this->depth++;

        return true;
    }

    public function leaveDepth(): void
    {
        if ($this->depth > 0) {
            $this->depth--;
        }
    }

    public function currentDepth(): int
    {
        return $this->depth;
    }

    /**
     * Mark an object as being processed. Returns false if it is already on the
     * stack, which means following it again would loop forever.
     */
    public function enterObject(object $object): bool
    {
        if ($this->activeObjects->contains($object)) {
            return false;
        }

        $this->activeObjects->attach($object);

        return true;
    }

    public function leaveObject(object $object): void
    {
        $this->activeObjects->detach($object);
    }

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
     * @return array<int, string>
     */
    public function getRedactedKeys(): array
    {
        return array_values(array_unique($this->redactedKeys));
    }

    /**
     * Record that a rule redacted something under the given key.
     *
     * The key may be empty (a bare string passed straight to redact()), in
     * which case only the redaction flag is set.
     */
    public function recordRedaction(string $key, ?string $rule = null): void
    {
        $this->wasRedacted = true;

        if ($key !== '') {
            $this->redactedKeys[] = $key;
        }
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
