<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Detection;

use Kirschbaum\Redactor\Operators\OperatorSpec;

/**
 * Something sensitive found at a known place in a known string.
 *
 * A detection says only what was found and where; what happens to it is an
 * operator's decision made later, so the same detection can be redacted in
 * one profile and pseudonymised in another. Offsets always refer to the
 * subject as the detector received it: detectors never rewrite, and the
 * context rewrites the original once, so a surrogate is never re-detected
 * and a finding's column never drifts.
 */
final readonly class Detection
{
    public function __construct(
        /** The kind of thing found: email, credit_card, aws_secret_key. */
        public string $entity,
        /** The rule that found it, for reporting and baselines. */
        public string $rule,
        /** The byte offset of the sensitive span within the subject. */
        public int $offset,
        /** The sensitive text itself. */
        public string $value,
        public Confidence $confidence,
        /** The key the subject was found under, where there was one. */
        public string $key = '',
        /** The operator the rule explicitly chose, or null to let the profile decide. */
        public ?OperatorSpec $operator = null,
        /** Whether the detector failed and the whole value must be replaced, whatever operator policy says. */
        public bool $failClosed = false,
        /** The rule's position in the profile's declared order, which settles equal-score overlaps. */
        public int $priority = PHP_INT_MAX,
    ) {}

    /**
     * Get the length of the sensitive span.
     */
    public function length(): int
    {
        return strlen($this->value);
    }

    /**
     * Get the offset just past the sensitive span.
     */
    public function end(): int
    {
        return $this->offset + $this->length();
    }

    /**
     * Create a copy of the detection with the given confidence.
     */
    public function withConfidence(Confidence $confidence): self
    {
        return new self(
            entity: $this->entity,
            rule: $this->rule,
            offset: $this->offset,
            value: $this->value,
            confidence: $confidence,
            key: $this->key,
            operator: $this->operator,
            failClosed: $this->failClosed,
            priority: $this->priority,
        );
    }

    /**
     * Create a detection covering the whole subject because the detector failed.
     */
    public static function failClosed(string $entity, string $rule, string $subject, string $key, string $reason): self
    {
        return new self(
            entity: $entity,
            rule: $rule,
            offset: 0,
            value: $subject,
            confidence: Confidence::of(Confidence::CERTAIN, $reason),
            key: $key,
            failClosed: true,
        );
    }

    /**
     * Determine if this detection covers the same ground as another.
     */
    public function overlaps(self $other): bool
    {
        return $this->offset < $other->end() && $other->offset < $this->end();
    }
}
