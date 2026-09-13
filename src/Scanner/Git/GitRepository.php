<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Scanner\Git;

use RuntimeException;
use Symfony\Component\Process\Process;

/**
 * The git commands the scanner needs, and nothing else.
 *
 * Every method yields patches of added lines, so a scan of "what is being
 * committed", "what this branch adds over main" and "everything ever
 * committed" all go through the same parser and the same scanner.
 */
final class GitRepository
{
    public function __construct(
        private readonly string $directory,
    ) {}

    public function isRepository(): bool
    {
        $process = $this->process(['rev-parse', '--is-inside-work-tree']);

        return $process->run() === 0 && trim($process->getOutput()) === 'true';
    }

    /**
     * The repository root, where git's paths are relative to.
     */
    public function root(): string
    {
        return trim($this->run(['rev-parse', '--show-toplevel']));
    }

    /**
     * Lines added by the changes currently staged for commit.
     *
     * @param  array<int, string>  $pathspec
     * @return array<int, Patch>
     */
    public function staged(array $pathspec = []): array
    {
        return PatchParser::parse($this->run([
            'diff', '--cached', '-U0', '--no-color', '--no-ext-diff', '--diff-filter=ACMR', ...self::spec($pathspec),
        ]));
    }

    /**
     * Lines the working tree adds over a ref: a branch over main, say.
     *
     * @param  array<int, string>  $pathspec
     * @return array<int, Patch>
     */
    public function diff(string $ref, array $pathspec = []): array
    {
        return PatchParser::parse($this->run([
            'diff', '-U0', '--no-color', '--no-ext-diff', '--diff-filter=ACMR', $ref, ...self::spec($pathspec),
        ]));
    }

    /**
     * Lines added by every commit in a range, newest first, each patch
     * carrying the hash of the commit that added it.
     *
     * A secret committed and removed two commits later is still in the
     * repository's history; this is the mode that finds it.
     *
     * @param  array<int, string>  $pathspec
     * @return array<int, Patch>
     */
    public function history(?string $range = null, array $pathspec = []): array
    {
        $arguments = ['log', '-p', '-U0', '--no-color', '--no-ext-diff', '--diff-filter=ACMR', '--format=commit %H'];

        if ($range !== null && $range !== '') {
            $arguments[] = $range;
        }

        return PatchParser::parse($this->run([...$arguments, ...self::spec($pathspec)]));
    }

    /**
     * @param  array<int, string>  $pathspec
     * @return array<int, string>
     */
    private static function spec(array $pathspec): array
    {
        return $pathspec === [] ? [] : ['--', ...$pathspec];
    }

    /**
     * @param  array<int, string>  $arguments
     */
    private function run(array $arguments): string
    {
        $process = $this->process($arguments);
        $process->run();

        if (! $process->isSuccessful()) {
            throw new RuntimeException(sprintf(
                'git %s failed: %s',
                $arguments[0],
                trim($process->getErrorOutput()) ?: 'exit code '.$process->getExitCode()
            ));
        }

        return $process->getOutput();
    }

    /**
     * @param  array<int, string>  $arguments
     */
    private function process(array $arguments): Process
    {
        $process = new Process(['git', ...$arguments], $this->directory);
        $process->setTimeout(null);

        return $process;
    }
}
