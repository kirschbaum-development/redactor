<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Scanner;

use Kirschbaum\Redactor\Findings\MatchFinding;
use Kirschbaum\Redactor\Redactor;

class Scanner
{
    /**
     * How much of a line to show in a finding's excerpt.
     */
    private const EXCERPT_LIMIT = 200;

    public function __construct(
        protected Redactor $redactor
    ) {}

    public function scanFile(string $filePath, ?string $profile = null, ?string $relativeTo = null): ScanResult
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

        $result = $this->redactor->redactWithMetadata($content, $profile);

        $reportedPath = $relativeTo !== null
            ? self::relativePath($filePath, $relativeTo)
            : $filePath;

        return new ScanResult(
            path: $filePath,
            findings: $this->locate($content, $result->value, $result->findings, $reportedPath, $profile ?? 'default'),
            profile: $profile ?? 'default'
        );
    }

    /**
     * Turn byte offsets into file positions.
     *
     * @param  array<int, MatchFinding>  $matches
     * @return array<int, ScanFinding>
     */
    protected function locate(string $original, mixed $redacted, array $matches, string $path, string $profile): array
    {
        if ($matches === []) {
            return [];
        }

        $lineStarts = self::lineStarts($original);

        // Replacements never introduce or remove newlines, so line N of the
        // redacted output corresponds to line N of the input - which is what
        // lets the excerpt come from the redacted text.
        $redactedLines = is_string($redacted) ? explode("\n", $redacted) : [];

        $findings = [];

        foreach ($matches as $match) {
            $line = self::lineForOffset($lineStarts, $match->offset);
            $column = $match->offset - $lineStarts[$line - 1] + 1;

            $findings[] = new ScanFinding(
                path: $path,
                rule: $match->rule,
                line: $line,
                column: $column,
                excerpt: self::excerpt($redactedLines[$line - 1] ?? ''),
                profile: $profile,
                fingerprint: ScanFinding::fingerprint($match->rule, $path, $match->matched),
            );
        }

        return $findings;
    }

    /**
     * Byte offset at which each line begins.
     *
     * @return array<int, int>
     */
    private static function lineStarts(string $content): array
    {
        $starts = [0];
        $offset = 0;

        while (($position = strpos($content, "\n", $offset)) !== false) {
            $starts[] = $position + 1;
            $offset = $position + 1;
        }

        return $starts;
    }

    /**
     * @param  array<int, int>  $lineStarts
     */
    private static function lineForOffset(array $lineStarts, int $offset): int
    {
        $low = 0;
        $high = count($lineStarts) - 1;

        while ($low < $high) {
            $mid = intdiv($low + $high + 1, 2);

            if ($lineStarts[$mid] <= $offset) {
                $low = $mid;
            } else {
                $high = $mid - 1;
            }
        }

        return $low + 1;
    }

    private static function excerpt(string $line): string
    {
        $line = trim(str_replace(["\r", "\t"], ['', ' '], $line));

        if (strlen($line) <= self::EXCERPT_LIMIT) {
            return $line;
        }

        return substr($line, 0, self::EXCERPT_LIMIT).'...';
    }

    private static function relativePath(string $path, string $base): string
    {
        $base = rtrim((string) (realpath($base) ?: $base), '/').'/';
        $real = realpath($path) ?: $path;

        return str_starts_with($real, $base) ? substr($real, strlen($base)) : $real;
    }
}
