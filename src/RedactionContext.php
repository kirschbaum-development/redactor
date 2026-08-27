<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor;

use Kirschbaum\Redactor\Detection\Detection;
use Kirschbaum\Redactor\Findings\MatchFinding;
use Kirschbaum\Redactor\Operators\OperatorContext;
use Kirschbaum\Redactor\Operators\OperatorRegistry;
use Kirschbaum\Redactor\Operators\OperatorSpec;
use Kirschbaum\Redactor\Patterns\PatternRule;
use Kirschbaum\Redactor\Support\InternalLog;
use Kirschbaum\Redactor\Support\Pseudonymizer;

class RedactionContext
{
    /** @var array<int, string> */
    private array $redactedKeys = [];

    /** @var array<int, MatchFinding> */
    private array $findings = [];

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

    private ?Pseudonymizer $pseudonymizer = null;

    private bool $pseudonymizerResolved = false;

    public function __construct(
        public readonly RedactorConfig $config,
        public readonly OperatorRegistry $operators = new OperatorRegistry,
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
     * Apply the configured operator to a detection.
     *
     * The single place detection turns into a decision, so every strategy gets
     * the same precedence rules and the same never-throw behaviour.
     */
    public function operate(Detection $detection, ?PatternRule $rule = null, ?OperatorSpec $atLocation = null): string
    {
        $spec = $this->config->policy->operatorFor($detection, $rule, $atLocation);

        if (! $this->operators->has($spec->name)) {
            InternalLog::warning('Unknown redaction operator; falling back to the replacement string', [
                'operator' => $spec->name,
                'profile' => $this->config->profile,
                'rule' => $detection->rule,
            ]);

            return $this->config->replacement;
        }

        return $this->operators->get($spec->name)->apply(
            $detection,
            new OperatorContext($this->config->replacement, $spec->options, $this->pseudonymizer()),
        );
    }

    /**
     * Whether a detection clears the profile's confidence floor.
     */
    public function accepts(Detection $detection): bool
    {
        return $detection->confidence->meets($this->config->minConfidence);
    }

    /**
     * The pseudonymizer for this profile, or null when none is configured.
     *
     * Resolved once and cached: deriving a key is cheap but not free, and a
     * misconfigured key must not raise on every value in a payload.
     */
    public function pseudonymizer(): ?Pseudonymizer
    {
        if ($this->pseudonymizerResolved) {
            return $this->pseudonymizer;
        }

        $this->pseudonymizerResolved = true;
        $this->pseudonymizer = PseudonymizerFactory::forProfile($this->config);

        return $this->pseudonymizer;
    }

    /**
     * Record that a rule redacted something under the given key.
     *
     * The key may be empty (a bare string passed straight to redact()), in
     * which case only the redaction flag is set.
     */
    public function recordRedaction(
        string $key,
        ?string $rule = null,
        int $offset = 0,
        int $length = 0,
        string $matched = '',
    ): void {
        $this->wasRedacted = true;

        if ($key !== '') {
            $this->redactedKeys[] = $key;
        }

        if ($rule !== null) {
            $this->findings[] = new MatchFinding(
                rule: $rule,
                key: $key,
                offset: $offset,
                length: $length,
                matched: $matched,
            );
        }
    }

    /**
     * Every match recorded during this redaction, in the order found.
     *
     * @return array<int, MatchFinding>
     */
    public function getFindings(): array
    {
        return $this->findings;
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
