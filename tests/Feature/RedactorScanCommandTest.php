
<?php

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;
use Mockery;

describe('RedactorScanCommand', function () {
    beforeEach(function () {
        // Ensure we're using the file_scan profile for consistent results
        config(['redactor.scan.profile' => 'file_scan']);

        // Create unreadable test files dynamically
        $unreadableContent = 'This file should not be readable by the scanner.';

        $unreadableFile1 = __DIR__.'/fixtures/unreadable-file.txt';
        $unreadableFile2 = __DIR__.'/fixtures/subdirectory/unreadable-file.txt';

        file_put_contents($unreadableFile1, $unreadableContent);
        file_put_contents($unreadableFile2, $unreadableContent);

        chmod($unreadableFile1, 0000);
        chmod($unreadableFile2, 0000);
    });

    afterEach(function () {
        // Clean up unreadable test files
        $unreadableFile1 = __DIR__.'/fixtures/unreadable-file.txt';
        $unreadableFile2 = __DIR__.'/fixtures/subdirectory/unreadable-file.txt';

        if (file_exists($unreadableFile1)) {
            chmod($unreadableFile1, 0644);
            unlink($unreadableFile1);
        }

        if (file_exists($unreadableFile2)) {
            chmod($unreadableFile2, 0644);
            unlink($unreadableFile2);
        }
    });

    it('scans a single clean file and shows clean status', function () {
        $exitCode = Artisan::call('redactor:scan', [
            'paths' => [__DIR__.'/fixtures/clean-text-file.txt'],
        ]);

        $output = Artisan::output();

        expect($exitCode)->toBe(0);
        expect($output)->toContain('CLEAN');
        expect($output)->toContain('Files scanned: 1');
        expect($output)->toContain('Files with findings: 0');
    });

    it('scans a single sensitive file and detects findings', function () {
        $exitCode = Artisan::call('redactor:scan', [
            'paths' => [__DIR__.'/fixtures/sensitive-api-keys.txt'],
        ]);

        $output = Artisan::output();

        expect($exitCode)->toBe(0);
        expect($output)->toContain('FINDINGS');
        expect($output)->toContain('Files scanned: 1');
        expect($output)->toContain('Files with findings: 1');
    });

    it('scans multiple files with mixed content', function () {
        $exitCode = Artisan::call('redactor:scan', [
            'paths' => [
                __DIR__.'/fixtures/clean-text-file.txt',
                __DIR__.'/fixtures/sensitive-api-keys.txt',
                __DIR__.'/fixtures/personal-info.txt',
            ],
        ]);

        $output = Artisan::output();

        expect($exitCode)->toBe(0);
        expect($output)->toContain('CLEAN');
        expect($output)->toContain('FINDINGS');
        expect($output)->toContain('Files scanned: 3');
        expect($output)->toContain('Files with findings: 2');
    });

    it('scans a directory and finds all files (excluding filtered files)', function () {
        $exitCode = Artisan::call('redactor:scan', [
            'paths' => [__DIR__.'/fixtures/subdirectory'],
        ]);

        $output = Artisan::output();

        expect($exitCode)->toBe(0);
        // Should still be 2 files - the large and unreadable files should be filtered out
        expect($output)->toContain('Files scanned: 2');
        expect($output)->toContain('nested-secrets.yml');
        expect($output)->toContain('clean-config.yml');
        // Should not contain the filtered files
        expect($output)->not->toContain('large-file.txt');
        expect($output)->not->toContain('unreadable-file.txt');
    });

    it('scans mixed files and directories', function () {
        $exitCode = Artisan::call('redactor:scan', [
            'paths' => [
                __DIR__.'/fixtures/clean-text-file.txt',
                __DIR__.'/fixtures/subdirectory',
            ],
        ]);

        $output = Artisan::output();

        expect($exitCode)->toBe(0);
        expect($output)->toContain('Files scanned: 3');
        expect($output)->toContain('clean-text-file.txt');
        expect($output)->toContain('nested-secrets.yml');
        expect($output)->toContain('clean-config.yml');
    });

    it('outputs results in JSON format', function () {
        $exitCode = Artisan::call('redactor:scan', [
            'paths' => [__DIR__.'/fixtures/clean-text-file.txt'],
            '--output' => 'json',
        ]);

        $output = Artisan::output();

        expect($exitCode)->toBe(0);

        // Extract JSON from output - find the JSON array part
        $jsonStart = strpos($output, '[');
        $jsonEnd = strrpos($output, ']') + 1;

        expect($jsonStart)->not->toBeFalse('JSON output should contain an array');

        $jsonOutput = substr($output, $jsonStart, $jsonEnd - $jsonStart);
        $data = json_decode($jsonOutput, true);

        expect($data)->toBeArray();
        expect($data[0]['status'])->toBe('clean');
        expect($data[0]['findings_count'])->toBe(0);
        expect($data[0]['profile'])->toBe('file_scan');
    });

    it('supports summary-only option', function () {
        $exitCode = Artisan::call('redactor:scan', [
            'paths' => [__DIR__.'/fixtures/clean-text-file.txt'],
            '--summary-only' => true,
        ]);

        $output = Artisan::output();

        expect($exitCode)->toBe(0);
        expect($output)->not->toContain('CLEAN'); // No table shown
        expect($output)->toContain('Files scanned: 1');
        expect($output)->toContain('Files with findings: 0');
    });

    it('exits with failure code when --bail is used and findings are detected', function () {
        $exitCode = Artisan::call('redactor:scan', [
            'paths' => [__DIR__.'/fixtures/sensitive-api-keys.txt'],
            '--bail' => true,
        ]);

        $output = Artisan::output();

        expect($exitCode)->toBe(1); // Failure exit code
        expect($output)->toContain('FINDINGS');
        expect($output)->toContain('Files with findings: 1');
    });

    it('exits with success code when --bail is used and no findings are detected', function () {
        $exitCode = Artisan::call('redactor:scan', [
            'paths' => [__DIR__.'/fixtures/clean-text-file.txt'],
            '--bail' => true,
        ]);

        $output = Artisan::output();

        expect($exitCode)->toBe(0); // Success exit code
        expect($output)->toContain('CLEAN');
        expect($output)->toContain('Files with findings: 0');
    });

    it('uses custom profile when specified', function () {
        $exitCode = Artisan::call('redactor:scan', [
            'paths' => [__DIR__.'/fixtures/clean-text-file.txt'],
            '--profile' => 'default',
        ]);

        $output = Artisan::output();

        expect($exitCode)->toBe(0);
        expect($output)->toContain('with profile: default');
    });

    it('defaults to base_path when no paths are provided', function () {
        $exitCode = Artisan::call('redactor:scan', []);

        $output = Artisan::output();

        expect($exitCode)->toBe(0);
        expect($output)->toContain('Scanning paths:');
        expect($output)->toContain('Files scanned:');
    });

    it('handles non-existent file gracefully', function () {
        $exitCode = Artisan::call('redactor:scan', [
            'paths' => [
                __DIR__.'/fixtures/non-existent-file.txt',
                __DIR__.'/fixtures/clean-text-file.txt',
            ],
        ]);

        $output = Artisan::output();

        expect($exitCode)->toBe(0);
        expect($output)->toContain('Path not found or not accessible');
        expect($output)->toContain('Files scanned: 1'); // Only the existing file
    });

    it('detects findings in various file types', function () {
        $testFiles = [
            'sensitive-api-keys.txt',
            'personal-info.txt',
            'sensitive-config.json',
            'environment-secrets.env',
            'high-entropy-strings.txt',
            'mixed-content.txt',
            'subdirectory/nested-secrets.yml',
        ];

        foreach ($testFiles as $file) {
            $exitCode = Artisan::call('redactor:scan', [
                'paths' => [__DIR__.'/fixtures/'.$file],
            ]);

            $output = Artisan::output();

            expect($exitCode)->toBe(0);
            expect($output)->toContain('FINDINGS');
            expect($output)->toContain('Files with findings: 1');
        }
    });

    it('identifies clean files correctly', function () {
        $testFiles = [
            'clean-text-file.txt',
            'clean-config.json',
            'subdirectory/clean-config.yml',
        ];

        foreach ($testFiles as $file) {
            $exitCode = Artisan::call('redactor:scan', [
                'paths' => [__DIR__.'/fixtures/'.$file],
            ]);

            $output = Artisan::output();

            expect($exitCode)->toBe(0);
            expect($output)->toContain('CLEAN');
            expect($output)->toContain('Files with findings: 0');
        }
    });

    it('provides detailed findings in JSON output', function () {
        $exitCode = Artisan::call('redactor:scan', [
            'paths' => [__DIR__.'/fixtures/sensitive-api-keys.txt'],
            '--output' => 'json',
        ]);

        $output = Artisan::output();

        expect($exitCode)->toBe(0);

        // Extract JSON from output - find the JSON array part
        $jsonStart = strpos($output, '[');
        $jsonEnd = strrpos($output, ']') + 1;

        expect($jsonStart)->not->toBeFalse('JSON output should contain an array');

        $jsonOutput = substr($output, $jsonStart, $jsonEnd - $jsonStart);
        $data = json_decode($jsonOutput, true);

        expect($data)->toBeArray();
        expect($data[0]['status'])->toBe('findings');
        expect($data[0]['findings_count'])->toBe(1);
        expect($data[0]['findings'][0]['type'])->toBe('full_content_redacted');
        expect($data[0]['profile'])->toBe('file_scan');
    });

    it('scans the original test fixture and finds redactions', function () {
        $exitCode = Artisan::call('redactor:scan', [
            'paths' => [__DIR__.'/fixtures/test-sensitive-file.txt'],
        ]);

        $output = Artisan::output();

        expect($exitCode)->toBe(0);
        expect($output)->toContain('FINDINGS');
        expect($output)->toContain('Files with findings: 1');
    });

    it('truncates long file paths in table output', function () {
        // Create a file with a very long path name
        $longPath = __DIR__.'/fixtures/this-is-a-very-long-filename-that-should-be-truncated-in-table-output.txt';
        File::copy(__DIR__.'/fixtures/clean-text-file.txt', $longPath);

        $exitCode = Artisan::call('redactor:scan', [
            'paths' => [$longPath],
        ]);

        $output = Artisan::output();

        expect($exitCode)->toBe(0);
        expect($output)->toContain('...');

        // Clean up
        File::delete($longPath);
    });

    it('filters out large and unreadable files during directory scanning', function () {
        // Get the count of files when scanning the entire fixtures directory
        $exitCode = Artisan::call('redactor:scan', [
            'paths' => [__DIR__.'/fixtures'],
            '--output' => 'json',
        ]);

        $output = Artisan::output();

        expect($exitCode)->toBe(0);

        // Extract JSON from output
        $jsonStart = strpos($output, '[');
        $jsonEnd = strrpos($output, ']') + 1;

        expect($jsonStart)->not->toBeFalse('JSON output should contain an array');

        $jsonOutput = substr($output, $jsonStart, $jsonEnd - $jsonStart);
        $data = json_decode($jsonOutput, true);

        // Verify that large-file.txt and unreadable-file.txt are not in the results
        $scannedPaths = collect($data)->pluck('path')->toArray();

        $foundLargeFile = false;
        $foundUnreadableFile = false;

        foreach ($scannedPaths as $path) {
            if (str_contains($path, 'large-file.txt')) {
                $foundLargeFile = true;
            }
            if (str_contains($path, 'unreadable-file.txt')) {
                $foundUnreadableFile = true;
            }
        }

        // These files should be filtered out due to size/permission constraints
        expect($foundLargeFile)->toBeFalse('large-file.txt should be filtered out due to size');
        expect($foundUnreadableFile)->toBeFalse('unreadable-file.txt should be filtered out due to permissions');

        // But we should still have scanned other files
        expect(count($data))->toBeGreaterThan(0, 'Should have scanned some files');
    });

    it('filters out large and unreadable files when specified as individual file paths', function () {
        // Try to scan the large and unreadable files directly
        $exitCode = Artisan::call('redactor:scan', [
            'paths' => [
                __DIR__.'/fixtures/large-file.txt',
                __DIR__.'/fixtures/unreadable-file.txt',
                __DIR__.'/fixtures/subdirectory/large-file.txt',
                __DIR__.'/fixtures/subdirectory/unreadable-file.txt',
                __DIR__.'/fixtures/clean-text-file.txt', // Include one valid file
            ],
            '--output' => 'json',
        ]);

        $output = Artisan::output();

        expect($exitCode)->toBe(0);

        // Extract JSON from output
        $jsonStart = strpos($output, '[');
        $jsonEnd = strrpos($output, ']') + 1;

        expect($jsonStart)->not->toBeFalse('JSON output should contain an array');

        $jsonOutput = substr($output, $jsonStart, $jsonEnd - $jsonStart);
        $data = json_decode($jsonOutput, true);

        // Should only have the clean file, filtered files should be excluded
        expect(count($data))->toBe(1, 'Should only scan the one readable, appropriately-sized file');
        expect($data[0]['path'])->toContain('clean-text-file.txt');
        expect($data[0]['status'])->toBe('clean');
    });

    it('displays skipped status when scanner returns skipped result', function () {
        // Mock Scanner to return a skipped result to test the display logic
        $mockScanner = Mockery::mock(\Kirschbaum\Redactor\Scanner\Scanner::class);
        $mockScanner->shouldReceive('scanFile')
            ->once()
            ->andReturn(new \Kirschbaum\Redactor\Scanner\ScanResult(
                path: 'test-file.txt',
                findings: [],
                profile: 'test',
                skipped: true,
                error: 'Test error'
            ));

        $this->app->instance(\Kirschbaum\Redactor\Scanner\Scanner::class, $mockScanner);

        $exitCode = Artisan::call('redactor:scan', [
            'paths' => [__DIR__.'/fixtures/clean-text-file.txt'],
        ]);

        $output = Artisan::output();

        expect($exitCode)->toBe(0);
        expect($output)->toContain('SKIPPED');
        expect($output)->toContain('Files scanned: 1');
        expect($output)->toContain('Files with findings: 0');
    });
});
