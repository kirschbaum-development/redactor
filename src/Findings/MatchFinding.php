<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Findings;

use Illuminate\Contracts\Support\Arrayable;
use JsonSerializable;
use Kirschbaum\Redactor\Detection\Confidence;

/**
 * One thing a strategy redacted, and where it was.
 *
 * Offsets are byte positions in the string the strategy was handed, which is
 * what the scanner needs to turn a finding into file:line:column. For a
 * key-based redaction the offset spans the whole value, since the key is the
 * signal rather than any span inside it.
 *
 * @implements Arrayable<string, mixed>
 */
final readonly class MatchFinding implements Arrayable, JsonSerializable
{
    public function __construct(
        public string $rule,
        public string $key = '',
        public int $offset = 0,
        public int $length = 0,
        public string $matched = '',
        /** What kind of thing was found; defaults to the rule that found it. */
        public ?string $entity = null,
        /** How sure the detector was and why; null where certainty is not a question, such as a blocked key. */
        public ?Confidence $confidence = null,
    ) {}

    /**
     * Get the kind of thing that was found.
     */
    public function entity(): string
    {
        return $this->entity ?? $this->rule;
    }

    /**
     * Get the finding as an array.
     *
     * The matched text is deliberately omitted.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'rule' => $this->rule,
            'entity' => $this->entity(),
            'key' => $this->key,
            'offset' => $this->offset,
            'length' => $this->length,
            'confidence' => $this->confidence?->score,
            'signals' => $this->confidence?->explain() ?? [],
        ];
    }

    /**
     * Convert the finding into something JSON serializable.
     *
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
