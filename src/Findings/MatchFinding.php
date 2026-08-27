<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Findings;

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
    ) {}
}
