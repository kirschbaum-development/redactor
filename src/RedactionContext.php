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
use Kirschbaum\Redactor\Recognition\RecognizerRegistry;
use Kirschbaum\Redactor\Support\InternalLog;
use Kirschbaum\Redactor\Support\Pseudonymizer;
use Kirschbaum\Redactor\Support\SecretRegistry;

class RedactionContext
{
    /** @var array<int, string> */
    private array $redactedKeys = [];

    /** @var array<int, MatchFinding> */
    private array $findings = [];

    /**
     * The objects currently on the recursion stack, used to break reference cycles.
     *
     * Keyed by spl_object_id rather than SplObjectStorage, whose contains() /
     * attach() / detach() trio is deprecated in PHP 8.5: a deprecation raised
     * inside a log tap becomes a log record, which is redacted, which raises it again.
     *
     * @var array<int, true>
     */
    private array $activeObjects = [];

    private int $depth = 0;

    /** @var array<string, float> */
    private array $entropyCache = [];

    /**
     * The detections reported for the value currently being processed, not yet acted on.
     *
     * @var array<int, Detection>
     */
    private array $pending = [];

    public bool $wasRedacted = false;

    private ?Pseudonymizer $pseudonymizer = null;

    private bool $pseudonymizerResolved = false;

    private ?SecretRegistry $secrets = null;

    public function __construct(
        public readonly RedactorConfig $config,
        public readonly OperatorRegistry $operators = new OperatorRegistry,
        /** Secrets registered at runtime, merged with the profile's own. */
        private readonly ?SecretRegistry $runtimeSecrets = null,
        private readonly ?RecognizerRegistry $recognizerRegistry = null,
    ) {}

    private ?RecognizerRegistry $defaultRecognizers = null;

    /**
     * Get the recognizer registry.
     */
    public function recognizers(): RecognizerRegistry
    {
        return $this->recognizerRegistry ?? ($this->defaultRecognizers ??= new RecognizerRegistry);
    }

    /**
     * Get every known secret in play, the profile's plus any registered at runtime.
     */
    public function secrets(): SecretRegistry
    {
        return $this->secrets ??= $this->runtimeSecrets instanceof SecretRegistry
            ? $this->config->knownSecrets->merge($this->runtimeSecrets)
            : $this->config->knownSecrets;
    }

    /**
     * Enter one level of nesting, returning false when the max depth would be exceeded.
     */
    public function enterDepth(): bool
    {
        if ($this->depth >= $this->config->maxDepth) {
            return false;
        }

        $this->depth++;

        return true;
    }

    /**
     * Leave one level of nesting.
     */
    public function leaveDepth(): void
    {
        if ($this->depth > 0) {
            $this->depth--;
        }
    }

    /**
     * Mark an object as being processed, returning false if it is already on the stack.
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

    /**
     * Mark an object as no longer being processed.
     */
    public function leaveObject(object $object): void
    {
        unset($this->activeObjects[spl_object_id($object)]);
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
     * The single place a detection turns into a decision, so every strategy
     * gets the same precedence rules and the same never-throw behaviour.
     */
    public function operate(Detection $detection, ?OperatorSpec $atLocation = null): string
    {
        $spec = $this->config->policy->operatorFor($detection, $atLocation);

        // Plain redaction is the common case and needs no operator context or registry lookup...
        if ($spec->name === OperatorRegistry::REDACT && $spec->options === []) {
            return $this->config->replacement;
        }

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
            new OperatorContext($this->config->replacement, $spec->options, fn (): ?\Kirschbaum\Redactor\Support\Pseudonymizer => $this->pseudonymizer()),
        );
    }

    /**
     * Get the operator the policy chooses for a detection, without applying it.
     *
     * For the whole-value sites, a blocked key or a path rule, where remove
     * and nullify change the record rather than the text and have to be
     * acted on by the walk itself.
     */
    public function operatorSpecFor(Detection $detection, ?OperatorSpec $atLocation = null): OperatorSpec
    {
        return $this->config->policy->operatorFor($detection, $atLocation);
    }

    /**
     * Determine if the profile's allowlist says the value is never sensitive.
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

    /**
     * Determine if any detections are pending.
     */
    public function hasPendingDetections(): bool
    {
        return $this->pending !== [];
    }

    /**
     * Drop the pending detections because a later strategy settled the value some other way.
     */
    public function discardPendingDetections(): void
    {
        $this->pending = [];
    }

    /**
     * Act on everything collected for a value, in one pass over it.
     *
     * The confidence floor and overlap resolution happen here, once, for every
     * detector alike. Offsets are trusted because every detector saw this
     * exact subject and nothing has rewritten it in between.
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
                // garbage into a log line, so skipping is the safe failure...
                continue;
            }

            if (! $detection->failClosed && $this->isAllowed($detection->value)) {
                continue;
            }

            $replacement = $detection->failClosed
                ? $this->config->replacement
                : $this->operate($detection);

            if ($replacement === $detection->value) {
                // A preserving operator: detected and reported, but deliberately left alone...
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
     * Get the pseudonymizer for this profile, or null when none is configured.
     *
     * Resolved once and cached, since a misconfigured key must not raise on
     * every value in a payload.
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
     * An empty key, a bare string passed straight to redact(), sets only the
     * redaction flag.
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
     * Get every match recorded during this redaction, in the order found.
     *
     * @return array<int, MatchFinding>
     */
    public function getFindings(): array
    {
        return $this->findings;
    }

    /**
     * Mark that a redaction occurred.
     */
    public function markRedacted(): void
    {
        $this->wasRedacted = true;
    }

    /**
     * Determine if any redaction occurred.
     */
    public function hasRedactions(): bool
    {
        return $this->wasRedacted;
    }

    /**
     * Get the cached entropy for a string.
     */
    public function getCachedEntropy(string $string): ?float
    {
        return $this->entropyCache[$string] ?? null;
    }

    /**
     * Cache the entropy of a string.
     */
    public function cacheEntropy(string $string, float $entropy): void
    {
        $this->entropyCache[$string] = $entropy;
    }
}
