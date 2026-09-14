<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Scanner;

use Generator;
use IteratorAggregate;

/**
 * Reads a file as overlapping windows of lines.
 *
 * Reading in windows keeps memory flat regardless of size, and the files most
 * worth scanning - logs, dumps, archives - are the large ones. Windows overlap
 * because a PEM block or a wrapped connection string can straddle a boundary;
 * the duplicate findings this produces are dropped by the scanner.
 *
 * @implements IteratorAggregate<int, array{0: int, 1: string}>
 */
class LineWindowReader implements IteratorAggregate
{
    public const DEFAULT_WINDOW_LINES = 512;

    public const DEFAULT_OVERLAP_LINES = 4;

    public function __construct(
        private readonly string $path,
        private readonly int $windowLines = self::DEFAULT_WINDOW_LINES,
        private readonly int $overlapLines = self::DEFAULT_OVERLAP_LINES,
        private readonly ?string $content = null,
    ) {}

    /**
     * Create a reader over in-memory text, such as a git patch.
     */
    public static function ofString(string $content, int $windowLines = self::DEFAULT_WINDOW_LINES, int $overlapLines = self::DEFAULT_OVERLAP_LINES): self
    {
        return new self('php://temp', $windowLines, $overlapLines, $content);
    }

    /**
     * @return Generator<int, array{0: int, 1: string}> [first line number, window text]
     */
    public function getIterator(): Generator
    {
        $handle = $this->content !== null
            ? fopen('php://temp', 'r+b')
            : @fopen($this->path, 'rb');

        if ($handle === false) {
            return;
        }

        if ($this->content !== null) {
            fwrite($handle, $this->content);
            rewind($handle);
        }

        // Overlap must be smaller than the window, or the reader never advances...
        $window = max(1, $this->windowLines);
        $overlap = max(0, min($this->overlapLines, $window - 1));

        try {
            $buffer = [];
            $startLine = 1;

            while (($line = fgets($handle)) !== false) {
                $buffer[] = rtrim($line, "\r\n");

                if (count($buffer) < $window) {
                    continue;
                }

                yield [$startLine, implode("\n", $buffer)];

                // Carry the tail forward so the next window sees a match that began in this one...
                $carried = $overlap > 0 ? array_slice($buffer, -$overlap) : [];
                $startLine += count($buffer) - count($carried);
                $buffer = $carried;
            }

            // The final partial window, unless it holds nothing but the overlap already emitted...
            if ($buffer !== [] && ($startLine === 1 || count($buffer) > $overlap)) {
                yield [$startLine, implode("\n", $buffer)];
            }
        } finally {
            fclose($handle);
        }
    }
}
