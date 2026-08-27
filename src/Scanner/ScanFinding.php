<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Scanner;

/**
 * One located finding: which rule fired, where, and what the line looks like
 * once redacted.
 *
 * The scanner previously emitted a single opaque record per file -
 * "full_content_redacted" with a length and nothing else - so there was no way
 * to know which rule fired or where to look.
 */
final readonly class ScanFinding
{
    public function __construct(
        public string $path,
        public string $rule,
        public int $line,
        public int $column,
        public string $excerpt,
        public string $profile,
        public string $fingerprint,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'rule' => $this->rule,
            'line' => $this->line,
            'column' => $this->column,
            'excerpt' => $this->excerpt,
            'profile' => $this->profile,
            'fingerprint' => $this->fingerprint,
        ];
    }

    /**
     * A stable identity for this finding.
     *
     * Derived from the rule, the file and the secret itself - never the line
     * number, so a finding accepted into a baseline stays accepted when the
     * code above it moves. The secret is hashed, never stored.
     */
    public static function fingerprint(string $rule, string $path, string $matched): string
    {
        return substr(hash('sha256', $rule.'|'.$path.'|'.$matched), 0, 32);
    }
}
