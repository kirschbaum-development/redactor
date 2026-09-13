<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Container\Container;
use Illuminate\Support\Collection;
use Kirschbaum\Redactor\Config\ConfigValue;
use Kirschbaum\Redactor\Exceptions\ConfigurationException;
use Kirschbaum\Redactor\Exceptions\GitException;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Scanner\Baseline;
use Kirschbaum\Redactor\Scanner\FileCollector;
use Kirschbaum\Redactor\Scanner\Git\GitRepository;
use Kirschbaum\Redactor\Scanner\Git\Patch;
use Kirschbaum\Redactor\Scanner\JunitReport;
use Kirschbaum\Redactor\Scanner\SarifReport;
use Kirschbaum\Redactor\Scanner\ScanFinding;
use Kirschbaum\Redactor\Scanner\Scanner;
use Kirschbaum\Redactor\Scanner\ScanResult;
use Kirschbaum\Redactor\Verification\SecretVerifier;
use Symfony\Component\Console\Attribute\AsCommand;

#[AsCommand(name: 'redactor:scan', description: 'Scan files for sensitive content using Redactor')]
class RedactorScanCommand extends Command
{
    protected $signature = 'redactor:scan
                            {paths?* : Paths to scan (files or directories, defaults to base_path); with a git mode, a pathspec}
                            {--profile=file_scan : Redaction profile to use}
                            {--bail : Exit with code 1 if findings are detected}
                            {--summary-only : Do not display per-file results}
                            {--output=table : Output format (table|json|sarif|junit)}
                            {--staged : Scan only the lines staged for commit}
                            {--diff= : Scan only the lines the working tree adds over this ref, e.g. origin/main}
                            {--history= : Scan the lines added by every commit, optionally in a range like main..HEAD}
                            {--min-confidence= : Ignore findings scoring below this (0-1)}
                            {--verify : Check detected credentials against their providers (sends them off this machine)}
                            {--baseline= : Path to a baseline file of accepted findings}
                            {--update-baseline : Write the current findings to the baseline file and exit 0}';

    public function handle(): int
    {
        /** @var array<int, string> $paths */
        $paths = $this->argument('paths');

        if ($paths === []) {
            $paths = [base_path()];
        }

        /** @var string $profile */
        $profile = $this->option('profile') ?? config('redactor.scan.profile', 'default');

        $bail = (bool) $this->option('bail');
        $summaryOnly = (bool) $this->option('summary-only');

        /** @var string $outputFormat */
        $outputFormat = $this->option('output') ?? 'table';

        if (! in_array($outputFormat, ['table', 'json', 'sarif', 'junit'], true)) {
            $this->components->error("Unknown --output format [{$outputFormat}]. Use table, json, sarif or junit.");

            return Command::FAILURE;
        }

        $gitMode = $this->gitMode();

        $minConfidence = $this->option('min-confidence');

        if (is_string($minConfidence) && $minConfidence !== '') {
            if (! is_numeric($minConfidence) || (float) $minConfidence < 0 || (float) $minConfidence > 1) {
                $this->components->error('--min-confidence must be a number between 0 and 1.');

                return Command::FAILURE;
            }

            // Applied to the profile rather than filtered afterwards, so a low-scoring detection is never acted on...
            config(["redactor.profiles.{$profile}.min_confidence" => (float) $minConfidence]);
        }

        $baselinePath = $this->baselinePath();
        $updateBaseline = (bool) $this->option('update-baseline');

        try {
            $baseline = $baselinePath !== null ? Baseline::load($baselinePath) : Baseline::empty();
        } catch (\JsonException $e) {
            $this->components->error($e->getMessage());

            return Command::FAILURE;
        }

        // Machine-readable output must not be polluted with progress chatter...
        $quiet = $outputFormat !== 'table';

        try {
            $ruleset = RedactorConfig::fromConfig($profile)->rulesetFingerprint;
        } catch (ConfigurationException $e) {
            $this->components->error($e->getMessage());

            return Command::FAILURE;
        }

        if (! $quiet && $baseline->ruleset !== null && $baseline->ruleset !== $ruleset) {
            $this->components->warn(sprintf(
                'The baseline was generated under ruleset %s; this scan runs ruleset %s. Findings it accepted may no longer mean the same thing - review it, or run --update-baseline.',
                $baseline->ruleset,
                $ruleset
            ));
        }

        if (! $quiet) {
            $this->components->info($gitMode === null
                ? 'Scanning paths: '.implode(', ', $paths)." with profile: {$profile}"
                : "Scanning {$gitMode} with profile: {$profile}");
        }

        $ignorePatterns = ConfigValue::stringList(
            config('redactor.scan.exclude_patterns', []),
            'scan.exclude_patterns'
        );

        // Config::array() and Config::integer() throw when the value arrives as a
        // string, which is exactly what env() produces for REDACTOR_SCAN_*...
        $maxFileSize = ConfigValue::positiveInt(
            config('redactor.scan.max_file_size'),
            10_485_760,
            'scan.max_file_size'
        );

        $skipBinary = ConfigValue::bool(config('redactor.scan.skip_binary'), true, 'scan.skip_binary');
        $respectGitignore = ConfigValue::bool(config('redactor.scan.respect_gitignore'), true, 'scan.respect_gitignore');

        $scanner = Container::getInstance()->make(Scanner::class);

        if ((bool) $this->option('verify')) {
            $verifier = SecretVerifier::fromConfig(
                ConfigValue::map(config('redactor.scan.verification', []), 'scan.verification')
            );

            if ($verifier === null) {
                $this->components->error(
                    'Verification is not enabled. Set redactor.scan.verification.enabled to true '
                    .'and list the providers you permit under redactor.scan.verification.verifiers.'
                );

                return Command::FAILURE;
            }

            // Verification sends real credentials to third parties, so say so before it happens...
            if (! $quiet) {
                $this->components->warn(sprintf(
                    'Verification is on: detected credentials will be sent to %s.',
                    implode(', ', $verifier->hosts())
                ));
            }

            $scanner = $scanner->withVerifier($verifier);
        }

        /** @var Collection<int, ScanResult> $results */
        $results = collect();

        if ($gitMode !== null) {
            try {
                $patches = $this->collectPatches($gitMode, $this->argument('paths'), $ignorePatterns);
            } catch (GitException $e) {
                $this->components->error($e->getMessage());

                return Command::FAILURE;
            }

            foreach ($patches as $patch) {
                $results->push($scanner->scanPatch($patch, $profile));
            }
        } else {
            $relativeTo = base_path();

            foreach ($this->collectFiles($paths, $ignorePatterns, $maxFileSize, $skipBinary, $respectGitignore, $quiet) as $file) {
                $results->push($scanner->scanFile($file, $profile, $relativeTo));
            }
        }

        /** @var Collection<int, ScanFinding> $allFindings */
        $allFindings = $results->flatMap(fn (ScanResult $r) => $r->findings);

        if ($updateBaseline) {
            return $this->writeBaseline($baselinePath, $allFindings->all(), $ruleset);
        }

        $suppressed = 0;

        if (! $baseline->isEmpty()) {
            $before = $allFindings->count();
            $results = $results->map(fn (ScanResult $r) => $r->withoutBaseline($baseline->fingerprints));
            $allFindings = $results->flatMap(fn (ScanResult $r) => $r->findings);
            $suppressed = $before - $allFindings->count();
        }

        $this->displayResults($results, $allFindings->all(), $outputFormat, $summaryOnly, $ruleset);

        $filesWithFindings = $results->filter(fn (ScanResult $r) => $r->hasFindings());

        if (! $quiet) {
            $this->newLine();
            $this->components->info($gitMode === null
                ? "Scan complete. Files scanned: {$results->count()}"
                : "Scan complete. Changes scanned: {$results->count()}");
            $this->components->info("Files with findings: {$filesWithFindings->count()}");
            $this->components->info("Total findings: {$allFindings->count()}");

            if ($suppressed > 0) {
                $this->components->info("Suppressed by baseline: {$suppressed}");
            }
        }

        return ($bail && $allFindings->isNotEmpty()) ? Command::FAILURE : Command::SUCCESS;
    }

    /**
     * Get the requested git mode, described for the operator.
     */
    protected function gitMode(): ?string
    {
        if ((bool) $this->option('staged')) {
            return 'staged changes';
        }

        $diff = $this->option('diff');

        if (is_string($diff) && $diff !== '') {
            return "changes over {$diff}";
        }

        if ($this->input->hasParameterOption('--history')) {
            $range = $this->option('history');

            return is_string($range) && $range !== '' ? "history {$range}" : 'full history';
        }

        return null;
    }

    /**
     * Collect the patches the chosen git mode produces, minus excluded paths.
     *
     * @param  array<int, string>  $pathspec
     * @param  array<int, string>  $ignorePatterns
     * @return array<int, Patch>
     *
     * @throws GitException when this is not a git repository or git fails
     */
    protected function collectPatches(string $mode, array $pathspec, array $ignorePatterns): array
    {
        $git = new GitRepository(base_path());

        if (! $git->isRepository()) {
            throw new GitException('['.base_path().'] is not inside a git repository.');
        }

        $patches = match (true) {
            (bool) $this->option('staged') => $git->staged($pathspec),
            is_string($this->option('diff')) && $this->option('diff') !== '' => $git->diff((string) $this->option('diff'), $pathspec),
            default => $git->history(is_string($this->option('history')) ? $this->option('history') : null, $pathspec),
        };

        return array_values(array_filter(
            $patches,
            fn (Patch $patch) => ! FileCollector::matchesExclude($patch->path, $ignorePatterns)
        ));
    }

    protected function baselinePath(): ?string
    {
        /** @var string|null $option */
        $option = $this->option('baseline');

        if (is_string($option) && $option !== '') {
            return $option;
        }

        $configured = config('redactor.scan.baseline');

        return is_string($configured) && $configured !== '' ? $configured : null;
    }

    /**
     * @param  array<int, ScanFinding>  $findings
     */
    protected function writeBaseline(?string $path, array $findings, ?string $ruleset = null): int
    {
        if ($path === null) {
            $this->components->error('--update-baseline needs a path: pass --baseline=<file> or set redactor.scan.baseline.');

            return Command::FAILURE;
        }

        if (! Baseline::write($path, $findings, now()->toIso8601String(), $ruleset)) {
            $this->components->error("Could not write baseline file [{$path}].");

            return Command::FAILURE;
        }

        $this->components->info(sprintf('Wrote %d accepted findings to %s', count($findings), $path));

        return Command::SUCCESS;
    }

    /**
     * Collect the files to scan from the given paths.
     *
     * @param  array<int, string>  $paths
     * @param  array<int, string>  $ignorePatterns
     * @return array<int, string>
     */
    protected function collectFiles(
        array $paths,
        array $ignorePatterns,
        int $maxFileSize,
        bool $skipBinary = true,
        bool $respectGitignore = true,
        bool $quiet = false
    ): array {
        // Warn about paths that do not exist...
        $validPaths = [];
        foreach ($paths as $path) {
            if (is_file($path) || is_dir($path)) {
                $validPaths[] = $path;
            } elseif (! $quiet) {
                $this->components->warn("Path not found or not accessible: {$path}");
            }
        }

        return FileCollector::collect(
            paths: $validPaths,
            excludePatterns: $ignorePatterns,
            maxSizeBytes: $maxFileSize,
            skipBinary: $skipBinary,
            respectGitignore: $respectGitignore
        );
    }

    /**
     * Display the scan results in the given format.
     *
     * @param  Collection<int, ScanResult>  $results
     * @param  array<int, ScanFinding>  $findings
     */
    protected function displayResults(Collection $results, array $findings, string $format, bool $summaryOnly, ?string $ruleset = null): void
    {
        match ($format) {
            'json' => $this->displayJsonResults($results, $ruleset),
            'sarif' => $this->displaySarifResults($findings, $ruleset),
            'junit' => $this->output->writeln(JunitReport::build($results->all())),
            default => $this->displayTableResults($results, $findings, $summaryOnly),
        };
    }

    /**
     * @param  Collection<int, ScanResult>  $results
     */
    protected function displayJsonResults(Collection $results, ?string $ruleset = null): void
    {
        $jsonData = $results->map(fn (ScanResult $r) => [
            'path' => $r->path,
            'ruleset' => $ruleset,
            'status' => $r->skipped ? 'skipped' : ($r->hasFindings() ? 'findings' : 'clean'),
            'findings_count' => count($r->findings),
            'findings' => array_map(fn (ScanFinding $f) => $f->toArray(), $r->findings),
            'profile' => $r->profile,
            'error' => $r->error,
        ])->toArray();

        $jsonOutput = json_encode($jsonData, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        if ($jsonOutput !== false) {
            $this->output->writeln($jsonOutput);
        }
    }

    /**
     * @param  array<int, ScanFinding>  $findings
     */
    protected function displaySarifResults(array $findings, ?string $ruleset = null): void
    {
        $sarif = json_encode(SarifReport::build($findings, '1.0.0', $ruleset), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        if ($sarif !== false) {
            $this->output->writeln($sarif);
        }
    }

    /**
     * @param  Collection<int, ScanResult>  $results
     * @param  array<int, ScanFinding>  $findings
     */
    protected function displayTableResults(Collection $results, array $findings, bool $summaryOnly): void
    {
        if ($summaryOnly) {
            return;
        }

        if ($findings === []) {
            $this->components->info(sprintf('No findings across %d files.', $results->count()));

            return;
        }

        // Findings, not files: a list of file names with a count next to each is nothing
        // you can act on. Sorted by severity so the certain findings are read first...
        $rank = fn (ScanFinding $f) => match ($f->severity()) {
            'critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1, default => 0,
        };

        usort($findings, fn (ScanFinding $a, ScanFinding $b) => [$rank($b), $b->confidence ?? 1.0]
            <=> [$rank($a), $a->confidence ?? 1.0]);

        $this->table(
            ['Severity', 'Rule', 'Location', 'Excerpt'],
            array_map(fn (ScanFinding $f) => [
                match ($f->severity()) {
                    'critical' => '<fg=white;bg=red>LIVE</>',
                    'high' => '<fg=red>HIGH</>',
                    'medium' => '<fg=yellow>MEDIUM</>',
                    'low' => '<fg=blue>LOW</>',
                    default => '<fg=gray>VERY LOW</>',
                },
                $f->rule,
                self::shorten($f->location(), 52),
                self::shorten($f->excerpt, 48),
            ], $findings)
        );

        $skipped = $results->filter(fn (ScanResult $r) => $r->skipped);

        foreach ($skipped as $result) {
            $this->components->warn("Skipped {$result->path}: {$result->error}");
        }
    }

    private static function shorten(string $value, int $limit = 60): string
    {
        return strlen($value) > $limit ? '...'.substr($value, -($limit - 3)) : $value;
    }
}
