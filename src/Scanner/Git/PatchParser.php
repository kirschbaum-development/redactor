<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Scanner\Git;

/**
 * Turns unified diff output into one Patch per changed file.
 *
 * Reads the output of `git diff -U0` and `git log -p -U0`, which is the same
 * format with `commit <hash>` lines between changes. Zero context lines are
 * assumed but not required: context and removed lines are simply skipped.
 */
class PatchParser
{
    /** @var array<int, Patch> */
    private array $patches = [];

    private ?string $commit = null;

    private ?string $path = null;

    /** @var array<int, string> */
    private array $added = [];

    private int $line = 0;

    private bool $binary = false;

    private function __construct() {}

    /**
     * @return array<int, Patch>
     */
    public static function parse(string $diff): array
    {
        $parser = new self;

        foreach (preg_split('/\r?\n/', $diff) ?: [] as $raw) {
            $parser->consume($raw);
        }

        $parser->flush();

        return $parser->patches;
    }

    private function consume(string $raw): void
    {
        if (str_starts_with($raw, 'commit ') && preg_match('/^commit ([0-9a-f]{7,40})\b/', $raw, $m) === 1) {
            $this->flush();
            $this->commit = $m[1];

            return;
        }

        if (str_starts_with($raw, 'diff --git ')) {
            $this->flush();

            return;
        }

        if (str_starts_with($raw, '+++ ')) {
            $target = substr($raw, 4);

            // A deleted file has nothing to scan.
            $this->path = $target === '/dev/null' ? null : self::unquote($target);

            return;
        }

        if (str_starts_with($raw, 'Binary files ')) {
            $this->binary = true;

            return;
        }

        if (str_starts_with($raw, '@@ ')) {
            // @@ -old[,count] +new[,count] @@
            $this->line = preg_match('/\+(\d+)/', $raw, $m) === 1 ? (int) $m[1] : 1;

            return;
        }

        if ($this->path === null) {
            return;
        }

        if (str_starts_with($raw, '+')) {
            $this->added[$this->line] = substr($raw, 1);
            $this->line++;

            return;
        }

        if (str_starts_with($raw, ' ')) {
            // A context line, present when the diff was not made with -U0.
            $this->line++;
        }

        // '-' lines and '\ No newline at end of file' advance nothing.
    }

    private function flush(): void
    {
        if ($this->path !== null && ! $this->binary && $this->added !== []) {
            $this->patches[] = new Patch($this->path, $this->added, $this->commit);
        }

        $this->path = null;
        $this->added = [];
        $this->binary = false;
    }

    /**
     * Strip the a/ or b/ prefix and undo git's C-style quoting.
     */
    private static function unquote(string $target): string
    {
        if (str_starts_with($target, '"') && str_ends_with($target, '"')) {
            $target = stripcslashes(substr($target, 1, -1));
        }

        return preg_replace('#^[ab]/#', '', $target) ?? $target;
    }
}
