<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Scanner\Git;

/**
 * The lines one change added to one file.
 *
 * Only additions matter to a scanner running on a change: a removed line is
 * leaving, and an unchanged one was already there to be found by a full scan
 * or accepted into the baseline. Scanning additions alone is what makes a
 * pre-commit hook fail on the secret being committed now and nothing else.
 */
final readonly class Patch
{
    /**
     * @param  array<int, string>  $addedLines  real line number in the new file => text
     */
    public function __construct(
        public string $path,
        public array $addedLines,
        public ?string $commit = null,
    ) {}

    public function isEmpty(): bool
    {
        return $this->addedLines === [];
    }

    /**
     * Get the added lines as one text, in order, for scanning.
     */
    public function text(): string
    {
        return implode("\n", array_values($this->addedLines));
    }

    /**
     * Get the real file line for the Nth line (1-based) of text().
     */
    public function lineAt(int $textLine): int
    {
        $keys = array_keys($this->addedLines);

        return $keys[$textLine - 1] ?? $textLine;
    }
}
