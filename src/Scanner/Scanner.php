<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Scanner;

use Kirschbaum\Redactor\Redactor;

class Scanner
{
    public function __construct(
        protected Redactor $redactor
    ) {}

    public function scanFile(string $filePath, ?string $profile = null): ScanResult
    {
        $content = @file_get_contents($filePath);

        if ($content === false) {
            return new ScanResult(
                path: $filePath,
                findings: [],
                profile: $profile ?? 'default',
                skipped: true,
                error: 'File unreadable'
            );
        }

        $redacted = $this->redactor->redact($content, $profile);

        /** @var array<int, array<string, mixed>> $findings */
        $findings = [];

        // Check for array-based redaction (structured data like JSON)
        if (is_array($redacted) && isset($redacted['_redacted']) && $redacted['_redacted'] === true) {
            /** @var array<int, array<string, mixed>> $findings */
            $findings = $redacted['_redacted_keys'] ?? [];
        }
        // Check for string-based redaction (plain text content)
        elseif (is_string($redacted) && $redacted !== $content) {
            $findings = $this->analyzeStringRedaction($content, $redacted, $profile ?? 'default');
        }

        return new ScanResult(
            path: $filePath,
            findings: $findings,
            profile: $profile ?? 'default'
        );
    }

    /**
     * Analyze differences between original and redacted string content.
     *
     * @return array<int, array<string, mixed>>
     */
    protected function analyzeStringRedaction(string $original, string $redacted, string $profile): array
    {
        if ($redacted === $original) {
            return [];
        }

        // Redaction now rewrites the matched spans rather than the whole
        // value, so "did anything change" is the signal, not "was the result
        // exactly the replacement string".
        return [[
            'type' => 'content_redacted',
            'reason' => 'Sensitive content was redacted',
            'original_length' => strlen($original),
            'redacted_length' => strlen($redacted),
            'profile' => $profile,
        ]];
    }
}
