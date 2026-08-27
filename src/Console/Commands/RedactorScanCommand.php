<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Config;
use Kirschbaum\Redactor\Config\ConfigValue;
use Kirschbaum\Redactor\Scanner\Baseline;
use Kirschbaum\Redactor\Scanner\FileCollector;
use Kirschbaum\Redactor\Scanner\SarifReport;
use Kirschbaum\Redactor\Scanner\ScanFinding;
use Kirschbaum\Redactor\Scanner\Scanner;
use Kirschbaum\Redactor\Scanner\ScanResult;
use Symfony\Component\Console\Attribute\AsCommand;

#[AsCommand(name: 'redactor:scan', description: 'Scan files for sensitive content using Redactor')]
class RedactorScanCommand extends Command
{
    protected $signature = 'redactor:scan
                            {paths?* : Paths to scan (files or directories, defaults to base_path)}
                            {--profile=file_scan : Redaction profile to use}
                            {--bail : Exit with code 1 if findings are detected}
                            {--summary-only : Do not display per-file results}
                            {--output=table : Output format (table|json|sarif)}
                            {--min-confidence= : Ignore findings scoring below this (0-1)}
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

        if (! in_array($outputFormat, ['table', 'json', 'sarif'], true)) {
            $this->components->error("Unknown --output format [{$outputFormat}]. Use table, json or sarif.");

            return Command::FAILURE;
        }

        $minConfidence = $this->option('min-confidence');

        if (is_string($minConfidence) && $minConfidence !== '') {
            if (! is_numeric($minConfidence) || (float) $minConfidence < 0 || (float) $minConfidence > 1) {
                $this->components->error('--min-confidence must be a number between 0 and 1.');

                return Command::FAILURE;
            }

            // Applied to the profile rather than filtered afterwards, so a
            // low-scoring detection is never acted on in the first place.
            Config::set("redactor.profiles.{$profile}.min_confidence", (float) $minConfidence);
        }

        $baselinePath = $this->baselinePath();
        $updateBaseline = (bool) $this->option('update-baseline');

        try {
            $baseline = $baselinePath !== null ? Baseline::load($baselinePath) : Baseline::empty();
        } catch (\JsonException $e) {
            $this->components->error($e->getMessage());

            return Command::FAILURE;
        }

        // Machine-readable output must not be polluted with progress chatter.
        $quiet = $outputFormat !== 'table';

        if (! $quiet) {
            $this->components->info('Scanning paths: '.implode(', ', $paths)." with profile: {$profile}");
        }

        $ignorePatterns = ConfigValue::stringList(
            Config::get('redactor.scan.exclude_patterns', []),
            'scan.exclude_patterns'
        );

        // Config::array()/Config::integer() throw when the value arrives as a
        // string, which is exactly what env() produces for REDACTOR_SCAN_*.
        $maxFileSize = ConfigValue::positiveInt(
            Config::get('redactor.scan.max_file_size'),
            10_485_760,
            'scan.max_file_size'
        );

        $skipBinary = ConfigValue::bool(Config::get('redactor.scan.skip_binary'), true, 'scan.skip_binary');
        $respectGitignore = ConfigValue::bool(Config::get('redactor.scan.respect_gitignore'), true, 'scan.respect_gitignore');

        $files = $this->collectFiles($paths, $ignorePatterns, $maxFileSize, $skipBinary, $respectGitignore, $quiet);

        $scanner = resolve(Scanner::class);
        $relativeTo = base_path();

        /** @var Collection<int, ScanResult> $results */
        $results = collect();

        foreach ($files as $file) {
            $results->push($scanner->scanFile($file, $profile, $relativeTo));
        }

        /** @var Collection<int, ScanFinding> $allFindings */
        $allFindings = $results->flatMap(fn (ScanResult $r) => $r->findings);

        if ($updateBaseline) {
            return $this->writeBaseline($baselinePath, $allFindings->all());
        }

        $suppressed = 0;

        if (! $baseline->isEmpty()) {
            $before = $allFindings->count();
            $results = $results->map(fn (ScanResult $r) => $r->withoutBaseline($baseline->fingerprints));
            $allFindings = $results->flatMap(fn (ScanResult $r) => $r->findings);
            $suppressed = $before - $allFindings->count();
        }

        $this->displayResults($results, $allFindings->all(), $outputFormat, $summaryOnly);

        $filesWithFindings = $results->filter(fn (ScanResult $r) => $r->hasFindings());

        if (! $quiet) {
            $this->newLine();
            $this->components->info("Scan complete. Files scanned: {$results->count()}");
            $this->components->info("Files with findings: {$filesWithFindings->count()}");
            $this->components->info("Total findings: {$allFindings->count()}");

            if ($suppressed > 0) {
                $this->components->info("Suppressed by baseline: {$suppressed}");
            }
        }

        return ($bail && $allFindings->isNotEmpty()) ? Command::FAILURE : Command::SUCCESS;
    }

    protected function baselinePath(): ?string
    {
        /** @var string|null $option */
        $option = $this->option('baseline');

        if (is_string($option) && $option !== '') {
            return $option;
        }

        $configured = Config::get('redactor.scan.baseline');

        return is_string($configured) && $configured !== '' ? $configured : null;
    }

    /**
     * @param  array<int, ScanFinding>  $findings
     */
    protected function writeBaseline(?string $path, array $findings): int
    {
        if ($path === null) {
            $this->components->error('--update-baseline needs a path: pass --baseline=<file> or set redactor.scan.baseline.');

            return Command::FAILURE;
        }

        if (! Baseline::write($path, $findings, now()->toIso8601String())) {
            $this->components->error("Could not write baseline file [{$path}].");

            return Command::FAILURE;
        }

        $this->components->info(sprintf('Wrote %d accepted findings to %s', count($findings), $path));

        return Command::SUCCESS;
    }

    /**
     * Collect files from the given paths (files or directories).
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
        // Check for non-existent paths and warn user
        $validPaths = [];
        foreach ($paths as $path) {
            if (is_file($path) || is_dir($path)) {
                $validPaths[] = $path;
            } elseif (! $quiet) {
                $this->components->warn("Path not found or not accessible: {$path}");
            }
        }

        // Let FileCollector handle all the filtering logic
        return FileCollector::collect(
            paths: $validPaths,
            excludePatterns: $ignorePatterns,
            maxSizeBytes: $maxFileSize,
            skipBinary: $skipBinary,
            respectGitignore: $respectGitignore
        );
    }

    /**
     * Display scan results in the specified format.
     *
     * @param  Collection<int, ScanResult>  $results
     * @param  array<int, ScanFinding>  $findings
     */
    protected function displayResults(Collection $results, array $findings, string $format, bool $summaryOnly): void
    {
        match ($format) {
            'json' => $this->displayJsonResults($results),
            'sarif' => $this->displaySarifResults($findings),
            default => $this->displayTableResults($results, $findings, $summaryOnly),
        };
    }

    /**
     * @param  Collection<int, ScanResult>  $results
     */
    protected function displayJsonResults(Collection $results): void
    {
        $jsonData = $results->map(fn (ScanResult $r) => [
            'path' => $r->path,
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
    protected function displaySarifResults(array $findings): void
    {
        $sarif = json_encode(SarifReport::build($findings), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

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

        // Findings, not files: a list of file names with a count next to each
        // tells you nothing you can act on.
        // Sorted by severity so the certain findings are read first, which is
        // the order anyone triaging actually wants.
        usort($findings, fn (ScanFinding $a, ScanFinding $b) => ($b->confidence ?? 1.0) <=> ($a->confidence ?? 1.0));

        $this->table(
            ['Severity', 'Rule', 'Location', 'Excerpt'],
            array_map(fn (ScanFinding $f) => [
                match ($f->severity()) {
                    'high' => '<fg=red>HIGH</>',
                    'medium' => '<fg=yellow>MEDIUM</>',
                    'low' => '<fg=blue>LOW</>',
                    default => '<fg=gray>VERY LOW</>',
                },
                $f->rule,
                self::shorten($f->path, 44).":{$f->line}:{$f->column}",
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
