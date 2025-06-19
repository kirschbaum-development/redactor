<?php

namespace Kirschbaum\Redactor\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Config;
use Kirschbaum\Redactor\Scanner\FileCollector;
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
                            {--output=table : Output format (table|json)}';

    public function handle(): int
    {
        /** @var array<int, string> $paths */
        $paths = $this->argument('paths');

        if (empty($paths)) {
            $paths = [base_path()];
        }

        /** @var string $profile */
        $profile = $this->option('profile') ?? config('redactor.scan.profile', 'default');

        /** @var bool $bail */
        $bail = $this->option('bail');

        /** @var bool $summaryOnly */
        $summaryOnly = $this->option('summary-only');

        /** @var string $outputFormat */
        $outputFormat = $this->option('output') ?? 'table';

        $this->components->info('Scanning paths: '.implode(', ', $paths)." with profile: {$profile}");

        /** @var array<int, string> $ignorePatterns */
        $ignorePatterns = Config::array('redactor.scan.exclude_patterns', []);

        /** @var int $maxFileSize */
        $maxFileSize = Config::integer('redactor.scan.max_file_size', 10_485_760);

        $files = $this->collectFiles($paths, $ignorePatterns, $maxFileSize);

        $scanner = resolve(Scanner::class);

        /** @var Collection<int, ScanResult> $results */
        $results = collect();

        foreach ($files as $file) {
            $result = $scanner->scanFile($file, $profile);
            $results->push($result);
        }

        $this->displayResults($results, $outputFormat, $summaryOnly);

        $findings = $results->filter(fn (ScanResult $r) => $r->hasFindings());

        $this->newLine();
        $this->components->info("Scan complete. Files scanned: {$results->count()}");
        $this->components->info("Files with findings: {$findings->count()}");

        return ($bail && $findings->count() > 0) ? Command::FAILURE : Command::SUCCESS;
    }

    /**
     * Collect files from the given paths (files or directories).
     *
     * @param  array<int, string>  $paths
     * @param  array<int, string>  $ignorePatterns
     * @return array<int, string>
     */
    protected function collectFiles(array $paths, array $ignorePatterns, int $maxFileSize): array
    {
        // Check for non-existent paths and warn user
        $validPaths = [];
        foreach ($paths as $path) {
            if (is_file($path) || is_dir($path)) {
                $validPaths[] = $path;
            } else {
                $this->components->warn("Path not found or not accessible: {$path}");
            }
        }

        // Let FileCollector handle all the filtering logic
        return FileCollector::collect(
            paths: $validPaths,
            excludePatterns: $ignorePatterns,
            maxSizeBytes: $maxFileSize
        );
    }

    /**
     * Display scan results in the specified format.
     *
     * @param  Collection<int, ScanResult>  $results
     */
    protected function displayResults(Collection $results, string $format, bool $summaryOnly): void
    {
        if ($format === 'json') {
            $this->displayJsonResults($results);
        } else {
            $this->displayTableResults($results, $summaryOnly);
        }
    }

    /**
     * Display results in JSON format.
     *
     * @param  Collection<int, ScanResult>  $results
     */
    protected function displayJsonResults(Collection $results): void
    {
        $jsonData = $results->map(fn (ScanResult $r) => [
            'path' => $r->path,
            'status' => $r->skipped ? 'skipped' : ($r->hasFindings() ? 'findings' : 'clean'),
            'findings_count' => count($r->findings),
            'findings' => $r->findings,
            'profile' => $r->profile,
            'error' => $r->error,
        ])->toArray();

        $jsonOutput = json_encode($jsonData, JSON_PRETTY_PRINT);
        if ($jsonOutput !== false) {
            $this->output->writeln($jsonOutput);
        }
    }

    /**
     * Display results in table format.
     *
     * @param  Collection<int, ScanResult>  $results
     */
    protected function displayTableResults(Collection $results, bool $summaryOnly): void
    {
        if ($summaryOnly) {
            return;
        }

        $tableData = $results->map(function (ScanResult $result) {
            $status = $result->skipped
                ? '<fg=yellow>SKIPPED</>'
                : ($result->hasFindings() ? '<fg=red>FINDINGS</>' : '<fg=green>CLEAN</>');

            $findingsCount = $result->skipped ? '-' : (string) count($result->findings);

            $path = $result->path;
            // Truncate very long paths for better table display
            if (strlen($path) > 60) {
                $path = '...'.substr($path, -57);
            }

            return [
                'Status' => $status,
                'Findings' => $findingsCount,
                'File Path' => $path,
            ];
        })->toArray();

        $this->table(['Status', 'Findings', 'File Path'], $tableData);
    }
}
