<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Scanner;

use Generator;
use IteratorAggregate;

/**
 * Reads a file as overlapping windows of lines.
 *
 * Scanning by loading the whole file caps the useful file size at whatever the
 * memory limit allows, which is exactly backwards: the files most worth
 * scanning - production logs, database dumps, exported archives - are the large
 * ones. Reading in windows keeps memory flat regardless of size.
 *
 * Windows overlap because a match can straddle a boundary. A PEM block, a
 * wrapped connection string or a pretty-printed JSON credential spans several
 * lines, and a reader that cut cleanly at the window edge would miss exactly
 * the secret it was looking for. The overlap costs a little duplicate work and
 * produces duplicate findings, which the scanner drops by fingerprint.
 *
 * @implements IteratorAggregate<int, array{0: int, 1: string}>
 */
final class LineWindowReader implements IteratorAggregate
{
    public const DEFAULT_WINDOW_LINES = 512;

    public const DEFAULT_OVERLAP_LINES = 4;

    public function __construct(
        private readonly string $path,
        private readonly int $windowLines = self::DEFAULT_WINDOW_LINES,
        private readonly int $overlapLines = self::DEFAULT_OVERLAP_LINES,
    ) {}

    /**
     * @return Generator<int, array{0: int, 1: string}> [first line number, window text]
     */
    public function getIterator(): Generator
    {
        $handle = @fopen($this->path, 'rb');

        if ($handle === false) {
            return;
        }

        // Overlap has to be smaller than the window, or the reader never
        // advances and the scan runs forever on a file it cannot finish.
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

                // Carry the tail forward so the next window can see a match
                // that began in this one.
                $carried = $overlap > 0 ? array_slice($buffer, -$overlap) : [];
                $startLine += count($buffer) - count($carried);
                $buffer = $carried;
            }

            // The final partial window, unless it holds nothing but the overlap
            // already emitted.
            if ($buffer !== [] && ($startLine === 1 || count($buffer) > $overlap)) {
                yield [$startLine, implode("\n", $buffer)];
            }
        } finally {
            fclose($handle);
        }
    }
}
