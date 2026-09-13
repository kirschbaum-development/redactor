<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Detection;

use Kirschbaum\Redactor\Operators\OperatorSpec;

/**
 * Something sensitive found at a known place in a known string.
 *
 * A detection says only *what was found and where*. What happens to it is an
 * Operator's decision, made later and separately. Keeping the two apart is what
 * lets the same detection be redacted in one profile, pseudonymised in another
 * and merely reported by the scanner - and what lets a verifier take the raw
 * value before anything replaces it.
 *
 * Offsets always refer to the subject as the detector received it. Detectors
 * never rewrite; the context collects every detection for a value, resolves
 * overlaps, and rewrites the original once. That is what keeps a surrogate
 * from being re-detected by the next detector, and a finding's column from
 * drifting after an earlier rule changed the string's length.
 */
final readonly class Detection
{
    public function __construct(
        /** The kind of thing found: email, credit_card, aws_secret_key. */
        public string $entity,
        /** The rule that found it, for reporting and baselines. */
        public string $rule,
        /** Byte offset of the sensitive span within the subject. */
        public int $offset,
        /** The sensitive text itself. */
        public string $value,
        public Confidence $confidence,
        /** The key the subject was found under, where there was one. */
        public string $key = '',
        /**
         * The operator the finding rule asked for, if it expressed a choice.
         *
         * Null means the profile decides. A rule that merely left its mode at
         * the default has not chosen, and must not outrank operators.default.
         */
        public ?OperatorSpec $operator = null,
        /**
         * Set when the detector could not evaluate the subject at all - a PCRE
         * failure, a tokeniser that gave up - and the only safe answer is to
         * replace the whole value with the plain replacement string, whatever
         * operator policy says. A surrogate of "we do not know" is meaningless.
         */
        public bool $failClosed = false,
        /**
         * Where the finding rule sits in the profile's declared order.
         *
         * Settles an equal-score overlap: the rule listed first wins. Carried
         * on the detection so detectors are free to evaluate rules in
         * whatever order is cheapest without changing the outcome.
         */
        public int $priority = PHP_INT_MAX,
    ) {}

    public function length(): int
    {
        return strlen($this->value);
    }

    public function end(): int
    {
        return $this->offset + $this->length();
    }

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
     * A detection that covers the whole subject because the detector failed.
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
     * Whether this detection covers the same ground as another.
     *
     * Two rules matching the same span is normal - a card number matches both
     * `credit_card` and a generic digit-run rule - and only one of them should
     * be allowed to rewrite it.
     */
    public function overlaps(self $other): bool
    {
        return $this->offset < $other->end() && $other->offset < $this->end();
    }
}
