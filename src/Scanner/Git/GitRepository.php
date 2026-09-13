<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Scanner\Git;

use Kirschbaum\Redactor\Exceptions\GitException;
use Symfony\Component\Process\Process;

/**
 * The git commands the scanner needs, and nothing else.
 *
 * Every method yields patches of added lines, so a scan of "what is being
 * committed", "what this branch adds over main" and "everything ever
 * committed" all go through the same parser and the same scanner.
 */
class GitRepository
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
     * Get the repository root, which git's paths are relative to.
     */
    public function root(): string
    {
        return trim($this->run(['rev-parse', '--show-toplevel']));
    }

    /**
     * Get the lines added by the changes currently staged for commit.
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
     * Get the lines the working tree adds over a ref, such as a branch over main.
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
     * Get the lines added by every commit in a range, newest first, with the commit that added each.
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
            throw new GitException(sprintf(
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
