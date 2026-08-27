<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Scanner;

use Kirschbaum\Redactor\Verification\VerificationResult;

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
        public string $entity = '',
        /** 0.0-1.0, or null where the rule is structural rather than inferred. */
        public ?float $confidence = null,
        /** @var array<int, string> */
        public array $signals = [],
        /** Set only when verification ran; never carries the secret itself. */
        public ?VerificationResult $verification = null,
    ) {}

    public function withVerification(VerificationResult $result): self
    {
        return new self(
            path: $this->path,
            rule: $this->rule,
            line: $this->line,
            column: $this->column,
            excerpt: $this->excerpt,
            profile: $this->profile,
            fingerprint: $this->fingerprint,
            entity: $this->entity,
            confidence: $this->confidence,
            signals: $this->signals,
            verification: $result,
        );
    }

    /**
     * A severity a human can sort by.
     */
    public function severity(): string
    {
        // A confirmed-live credential outranks anything confidence can say:
        // certainty that it works beats an estimate that it exists.
        if ($this->verification !== null && $this->verification->status->isActive()) {
            return 'critical';
        }

        return match (true) {
            $this->confidence === null => 'high',
            $this->confidence >= 0.9 => 'high',
            $this->confidence >= 0.6 => 'medium',
            $this->confidence >= 0.3 => 'low',
            default => 'very-low',
        };
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'rule' => $this->rule,
            'entity' => $this->entity,
            'line' => $this->line,
            'column' => $this->column,
            'excerpt' => $this->excerpt,
            'confidence' => $this->confidence,
            'severity' => $this->severity(),
            // Why the score is what it is, so a threshold can be chosen on
            // evidence rather than by trial and error.
            'signals' => $this->signals,
            'verification' => $this->verification?->toArray(),
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
