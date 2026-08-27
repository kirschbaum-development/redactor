<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Detection;

/**
 * Something sensitive found at a known place in a known string.
 *
 * A detection says only *what was found and where*. What happens to it is an
 * Operator's decision, made later and separately. Keeping the two apart is what
 * lets the same detection be redacted in one profile, pseudonymised in another
 * and merely reported by the scanner - and what lets a verifier take the raw
 * value before anything replaces it.
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
