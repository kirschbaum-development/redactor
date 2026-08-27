<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Findings;

use Kirschbaum\Redactor\Detection\Confidence;

/**
 * One thing a strategy redacted, and where it was.
 *
 * Offsets are byte positions in the string the strategy was handed, which is
 * what the scanner needs to turn a finding into file:line:column. For a
 * key-based redaction the offset spans the whole value, since the key is the
 * signal rather than any span inside it.
 */
final readonly class MatchFinding
{
    public function __construct(
        public string $rule,
        public string $key = '',
        public int $offset = 0,
        public int $length = 0,
        public string $matched = '',
        /** What kind of thing was found; defaults to the rule that found it. */
        public ?string $entity = null,
        /**
         * How sure the detector was, and why.
         *
         * Null where certainty is not a question - a blocked key or a length
         * limit is a rule about structure, not an inference about content.
         */
        public ?Confidence $confidence = null,
    ) {}

    public function entity(): string
    {
        return $this->entity ?? $this->rule;
    }
}
