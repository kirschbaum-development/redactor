<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Scanner;

use Kirschbaum\Redactor\Findings\MatchFinding;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Scanner\Decoding\Decoder;
use Kirschbaum\Redactor\Scanner\Decoding\DerivedSubject;
use Kirschbaum\Redactor\Scanner\Git\Patch;
use Kirschbaum\Redactor\Verification\SecretVerifier;
use Kirschbaum\Redactor\Verification\VerificationResult;

class Scanner
{
    /**
     * How much of a line to show in a finding's excerpt.
     */
    private const int EXCERPT_LIMIT = 200;

    /**
     * A marker on the same line that suppresses the finding.
     *
     *     $key = 'sk_test_4eC39HqLyjWDarjtT1zdp7dc'; // redactor:allow
     *
     * For the fixture, the documented example, the sandbox credential - the
     * things a baseline would also accept, except that the reason travels with
     * the code instead of living in a JSON file nobody reads.
     */
    public const ALLOW_MARKER = 'redactor:allow';

    public function __construct(
        protected Redactor $redactor,
        protected int $windowLines = LineWindowReader::DEFAULT_WINDOW_LINES,
        protected int $overlapLines = LineWindowReader::DEFAULT_OVERLAP_LINES,
        /** Verifies while the raw value is in hand; only the verdict reaches a ScanFinding, never the secret. */
        protected ?SecretVerifier $verifier = null,
        /** Whether to look one layer deep inside base64, URL-encoded and JSON-escaped spans. */
        protected bool $decode = true,
    ) {}

    public function withVerifier(?SecretVerifier $verifier): self
    {
        return new self($this->redactor, $this->windowLines, $this->overlapLines, $verifier, $this->decode);
    }

    /**
     * Scan a file, a window of lines at a time.
     *
     * Streaming is unconditional rather than only for large files: a code path
     * that runs only on the rare large input is the one that ends up buggy.
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

        $reportedPath = $relativeTo !== null
            ? $this->relativePath($filePath, $relativeTo)
            : $filePath;

        return $this->scanWindows(
            new LineWindowReader($filePath, $this->windowLines, $this->overlapLines),
            $filePath,
            $reportedPath,
            $profile
        );
    }

    /**
     * Scan text held in memory as though it were a file at the given path.
     */
    public function scanText(string $content, string $path, ?string $profile = null): ScanResult
    {
        return $this->scanWindows(
            LineWindowReader::ofString($content, $this->windowLines, $this->overlapLines),
            $path,
            $path,
            $profile
        );
    }

    /**
     * Scan the lines a change added, reporting each finding at its real line and commit.
     *
     * The added lines are scanned as one text so a secret spanning two adjacent
     * added lines is still found; line numbers are then mapped back through the patch.
     */
    public function scanPatch(Patch $patch, ?string $profile = null): ScanResult
    {
        $result = $this->scanText($patch->text(), $patch->path, $profile);

        if (! $result->hasFindings()) {
            return $result;
        }

        return new ScanResult(
            path: $result->path,
            findings: array_map(
                fn (ScanFinding $finding): ScanFinding => $finding->at($patch->lineAt($finding->line), $patch->commit),
                $result->findings
            ),
            profile: $result->profile,
        );
    }

    private function scanWindows(LineWindowReader $reader, string $filePath, string $reportedPath, ?string $profile): ScanResult
    {
        $profileName = $profile ?? 'default';

        /** @var array<string, ScanFinding> $findings */
        $findings = [];

        foreach ($reader as [$startLine, $window]) {
            $result = $this->redactor->inspect($window, $profile);

            $located = $this->located($window, $result->value, $result->findings, $reportedPath, $profileName);

            if ($this->decode) {
                foreach (Decoder::derive($window) as $derived) {
                    foreach ($this->locatedInDerived($derived, $window, $reportedPath, $profile, $profileName) as $finding) {
                        $located[] = $finding;
                    }
                }
            }

            foreach ($located as $finding) {
                $absolute = $finding->at($startLine + $finding->line - 1, null);

                // Overlapping windows see the same span twice; identity is the rule and the place...
                $findings[$absolute->rule.'|'.$absolute->line.'|'.$absolute->column] = $absolute;
            }
        }

        $ordered = array_values($findings);

        usort($ordered, fn (ScanFinding $a, ScanFinding $b): int => [$a->line, $a->column] <=> [$b->line, $b->column]);

        return new ScanResult(
            path: $filePath,
            findings: $ordered,
            profile: $profileName
        );
    }

    /**
     * Locate and verify one window's matches.
     *
     * @param  array<int, MatchFinding>  $matches
     * @return array<int, ScanFinding>
     */
    private function located(string $window, mixed $redacted, array $matches, string $path, string $profileName): array
    {
        $verdicts = $this->verifyAll($matches);
        $findings = [];

        foreach ($this->locate($window, $redacted, $matches, $path, $profileName) as $index => $finding) {
            $findings[] = isset($verdicts[$index]) ? $finding->withVerification($verdicts[$index]) : $finding;
        }

        return $findings;
    }

    /**
     * Scan text recovered from an encoded span, reporting findings at the span's own position.
     *
     * The excerpt comes from the decoded, redacted text so the report shows
     * what was found without repeating it.
     *
     * @return array<int, ScanFinding>
     */
    private function locatedInDerived(DerivedSubject $derived, string $window, string $path, ?string $profile, string $profileName): array
    {
        $result = $this->redactor->inspect($derived->text, $profile);

        if ($result->findings === []) {
            return [];
        }

        $lineStarts = $this->lineStarts($window);
        $line = $this->lineForOffset($lineStarts, $derived->offset);
        $column = $derived->offset - $lineStarts[$line - 1] + 1;
        $verdicts = $this->verifyAll($result->findings);
        $redacted = is_string($result->value) ? $result->value : '';

        $findings = [];

        foreach ($result->findings as $index => $match) {
            $finding = new ScanFinding(
                path: $path,
                rule: $match->rule,
                line: $line,
                column: $column,
                excerpt: sprintf('[%s] %s', $derived->encoding, $this->excerpt(strtok($redacted, "\n") ?: '')),
                profile: $profileName,
                fingerprint: ScanFinding::fingerprint($match->rule, $path, $match->matched),
                entity: $match->entity(),
                confidence: $match->confidence?->score,
                signals: $match->confidence?->explain() ?? [],
                encoding: $derived->encoding,
            );

            $findings[] = isset($verdicts[$index]) ? $finding->withVerification($verdicts[$index]) : $finding;
        }

        return $findings;
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
        if (! $this->verifier instanceof SecretVerifier) {
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
     * Turn the byte offsets of the matches into file positions.
     *
     * @param  array<int, MatchFinding>  $matches
     * @return array<int, ScanFinding>
     */
    protected function locate(string $original, mixed $redacted, array $matches, string $path, string $profile): array
    {
        if ($matches === []) {
            return [];
        }

        $lineStarts = $this->lineStarts($original);

        // Replacements never add or remove newlines, so line N of the redacted output
        // is line N of the input, which is what lets the excerpt come from it...
        $redactedLines = is_string($redacted) ? explode("\n", $redacted) : [];
        $originalLines = str_contains($original, self::ALLOW_MARKER) ? explode("\n", $original) : null;

        $findings = [];

        foreach ($matches as $match) {
            $line = $this->lineForOffset($lineStarts, $match->offset);
            $column = $match->offset - $lineStarts[$line - 1] + 1;

            if ($originalLines !== null && str_contains($originalLines[$line - 1] ?? '', self::ALLOW_MARKER)) {
                continue;
            }

            $findings[] = new ScanFinding(
                path: $path,
                rule: $match->rule,
                line: $line,
                column: $column,
                excerpt: $this->excerpt($redactedLines[$line - 1] ?? ''),
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
     * Get the byte offset at which each line begins.
     *
     * @return array<int, int>
     */
    private function lineStarts(string $content): array
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
    private function lineForOffset(array $lineStarts, int $offset): int
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

    private function excerpt(string $line): string
    {
        $line = trim(str_replace(["\r", "\t"], ['', ' '], $line));

        if (strlen($line) <= self::EXCERPT_LIMIT) {
            return $line;
        }

        return substr($line, 0, self::EXCERPT_LIMIT).'...';
    }

    private function relativePath(string $path, string $base): string
    {
        $base = rtrim(realpath($base) ?: $base, '/').'/';
        $real = realpath($path) ?: $path;

        return str_starts_with($real, $base) ? substr($real, strlen($base)) : $real;
    }
}
