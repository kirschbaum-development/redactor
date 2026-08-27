<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Scanner;

use Kirschbaum\Redactor\Findings\MatchFinding;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Verification\SecretVerifier;
use Kirschbaum\Redactor\Verification\VerificationResult;

class Scanner
{
    /**
     * How much of a line to show in a finding's excerpt.
     */
    private const EXCERPT_LIMIT = 200;

    public function __construct(
        protected Redactor $redactor,
        protected int $windowLines = LineWindowReader::DEFAULT_WINDOW_LINES,
        protected int $overlapLines = LineWindowReader::DEFAULT_OVERLAP_LINES,
        /**
         * Verification happens here, while the raw value is still in hand, and
         * only the verdict is attached to the finding. The secret itself never
         * reaches a ScanFinding, so it cannot escape through JSON, SARIF or a
         * baseline file.
         */
        protected ?SecretVerifier $verifier = null,
    ) {}

    public function withVerifier(?SecretVerifier $verifier): self
    {
        return new self($this->redactor, $this->windowLines, $this->overlapLines, $verifier);
    }

    /**
     * Scan a file, a window of lines at a time.
     *
     * Streaming unconditionally rather than only for large files: a second code
     * path that runs on most inputs and a first that runs on the rare large one
     * guarantees the rarely-exercised path is the buggy one.
     */
    public function scanFile(string $filePath, ?string $profile = null, ?string $relativeTo = null): ScanResult
    {
        if (! is_readable($filePath) || ! is_file($filePath)) {
            return new ScanResult(
                path: $filePath,
                findings: [],
                profile: $profile ?? 'default',
                skipped: true,
                error: 'File unreadable'
            );
        }

        $profileName = $profile ?? 'default';

        $reportedPath = $relativeTo !== null
            ? self::relativePath($filePath, $relativeTo)
            : $filePath;

        /** @var array<string, ScanFinding> $findings */
        $findings = [];

        foreach (new LineWindowReader($filePath, $this->windowLines, $this->overlapLines) as [$startLine, $window]) {
            $result = $this->redactor->redactWithMetadata($window, $profile);

            if ($result->findings === []) {
                continue;
            }

            $verdicts = $this->verifyAll($result->findings);

            foreach ($this->locate($window, $result->value, $result->findings, $reportedPath, $profileName) as $index => $finding) {
                $absolute = new ScanFinding(
                    path: $finding->path,
                    rule: $finding->rule,
                    line: $startLine + $finding->line - 1,
                    column: $finding->column,
                    excerpt: $finding->excerpt,
                    profile: $finding->profile,
                    fingerprint: $finding->fingerprint,
                    entity: $finding->entity,
                    confidence: $finding->confidence,
                    signals: $finding->signals,
                );

                if (isset($verdicts[$index])) {
                    $absolute = $absolute->withVerification($verdicts[$index]);
                }

                // Overlapping windows see the same span twice; identity is the
                // rule and the place, not the order it was found in.
                $findings[$absolute->rule.'|'.$absolute->line.'|'.$absolute->column] = $absolute;
            }
        }

        $ordered = array_values($findings);

        usort($ordered, fn (ScanFinding $a, ScanFinding $b) => [$a->line, $a->column] <=> [$b->line, $b->column]);

        return new ScanResult(
            path: $filePath,
            findings: $ordered,
            profile: $profileName
        );
    }

    /**
     * Verify each detection, if anything is permitted to.
     *
     * Keyed by position so the verdict lands on the right finding without the
     * secret having to travel alongside it.
     *
     * @param  array<int, MatchFinding>  $matches
     * @return array<int, VerificationResult>
     */
    protected function verifyAll(array $matches): array
    {
        if ($this->verifier === null) {
            return [];
        }

        $verdicts = [];

        foreach ($matches as $index => $match) {
            if ($match->matched === '' || ! $this->verifier->canVerify($match->entity(), $match->rule)) {
                continue;
            }

            $verdicts[$index] = $this->verifier->verify($match->entity(), $match->rule, $match->matched);
        }

        return $verdicts;
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
                entity: $match->entity(),
                confidence: $match->confidence?->score,
                signals: $match->confidence?->explain() ?? [],
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
