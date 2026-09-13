<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor;

use Kirschbaum\Redactor\Detection\Confidence;
use Kirschbaum\Redactor\Detection\Detection;
use Kirschbaum\Redactor\Detection\DetectionSet;
use Kirschbaum\Redactor\Findings\MatchFinding;
use Kirschbaum\Redactor\Operators\OperatorContext;
use Kirschbaum\Redactor\Operators\OperatorRegistry;
use Kirschbaum\Redactor\Operators\OperatorSpec;
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
     * Keyed by spl_object_id rather than held in an SplObjectStorage: the
     * contains()/attach()/detach() trio is deprecated in PHP 8.5, and a
     * deprecation raised inside a log tap becomes a log record, which is
     * redacted, which raises the deprecation again.
     *
     * @var array<int, true>
     */
    private array $activeObjects = [];

    private int $depth = 0;

    /** @var array<string, float> */
    private array $entropyCache = [];

    /**
     * What the detecting strategies have reported about the value currently
     * being processed, before any of it has been acted on.
     *
     * @var array<int, Detection>
     */
    private array $pending = [];

    public bool $wasRedacted = false;

    private ?Pseudonymizer $pseudonymizer = null;

    private bool $pseudonymizerResolved = false;

    public function __construct(
        public readonly RedactorConfig $config,
        public readonly OperatorRegistry $operators = new OperatorRegistry,
    ) {}

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
        $id = spl_object_id($object);

        if (isset($this->activeObjects[$id])) {
            return false;
        }

        $this->activeObjects[$id] = true;

        return true;
    }

    public function leaveObject(object $object): void
    {
        unset($this->activeObjects[spl_object_id($object)]);
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
    public function operate(Detection $detection, ?OperatorSpec $atLocation = null): string
    {
        $spec = $this->config->policy->operatorFor($detection, $atLocation);

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
     * Whether the profile's allowlist says this value is never sensitive.
     */
    public function isAllowed(string $value): bool
    {
        return $this->config->allowlist->allows($value);
    }

    /**
     * Hold a detection until every detector has had its turn on the value.
     */
    public function collect(Detection $detection): void
    {
        $this->pending[] = $detection;
    }

    public function hasPendingDetections(): bool
    {
        return $this->pending !== [];
    }

    /**
     * Drop what was collected, because a later strategy settled the value
     * some other way - preserved it, or replaced it wholesale.
     */
    public function discardPendingDetections(): void
    {
        $this->pending = [];
    }

    /**
     * Act on everything collected for a value, in one pass over it.
     *
     * The confidence floor and overlap resolution happen here, once, for
     * every detector alike. Offsets are trusted because every detector saw
     * this exact subject: nothing has rewritten it in between.
     */
    public function resolvePendingDetections(string $subject, string $key): string
    {
        $kept = DetectionSet::resolve($this->pending, $this->config->minConfidence);
        $this->pending = [];

        if ($kept === []) {
            return $subject;
        }

        $out = '';
        $cursor = 0;
        $changed = false;

        foreach ($kept as $detection) {
            if ($detection->offset < $cursor) {
                // Cannot happen after resolve(), but a bug here would splice
                // garbage into a log line; skipping is the safe failure.
                continue;
            }

            if (! $detection->failClosed && $this->isAllowed($detection->value)) {
                continue;
            }

            $replacement = $detection->failClosed
                ? $this->config->replacement
                : $this->operate($detection);

            if ($replacement === $detection->value) {
                // A preserving operator: detected and reported, deliberately
                // left alone. The report is the point.
                $this->recordDetection($detection, redacted: false);

                continue;
            }

            $out .= substr($subject, $cursor, $detection->offset - $cursor).$replacement;
            $cursor = $detection->end();
            $changed = true;

            $this->recordDetection($detection);
        }

        return $changed ? $out.substr($subject, $cursor) : $subject;
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
        ?string $entity = null,
        ?Confidence $confidence = null,
        bool $redacted = true,
    ): void {
        if ($redacted) {
            $this->wasRedacted = true;

            if ($key !== '') {
                $this->redactedKeys[] = $key;
            }
        }

        if ($rule !== null) {
            $this->findings[] = new MatchFinding(
                rule: $rule,
                key: $key,
                offset: $offset,
                length: $length,
                matched: $matched,
                entity: $entity,
                confidence: $confidence,
            );
        }
    }

    /**
     * Record a detection, carrying its entity and score through to the report.
     */
    public function recordDetection(Detection $detection, bool $redacted = true): void
    {
        $this->recordRedaction(
            key: $detection->key,
            rule: $detection->rule,
            offset: $detection->offset,
            length: $detection->length(),
            matched: $detection->value,
            entity: $detection->entity,
            confidence: $detection->confidence,
            redacted: $redacted,
        );
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
