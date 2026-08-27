<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Kirschbaum\Redactor\Scanner\Baseline;
use Kirschbaum\Redactor\Scanner\ScanFinding;

function fixture(string $name): string
{
    return __DIR__.'/fixtures/'.$name;
}

function scan(array $arguments = []): array
{
    $exitCode = Artisan::call('redactor:scan', $arguments);

    return [$exitCode, Artisan::output()];
}

describe('RedactorScanCommand output', function () {
    beforeEach(function () {
        config(['redactor.scan.profile' => 'file_scan']);
        config(['redactor.scan.baseline' => null]);
    });

    it('reports a clean file as clean', function () {
        [$exitCode, $output] = scan(['paths' => [fixture('clean-text-file.txt')]]);

        expect($exitCode)->toBe(0)
            ->and($output)->toContain('No findings')
            ->and($output)->toContain('Files scanned: 1')
            ->and($output)->toContain('Total findings: 0');
    });

    it('names the rule and the line for each finding', function () {
        // The old output was one opaque row per file - "FINDINGS 1 <path>" -
        // with no way to know which rule fired or where to look.
        [$exitCode, $output] = scan(['paths' => [fixture('sensitive-api-keys.txt')]]);

        expect($exitCode)->toBe(0)
            ->and($output)->toContain('Rule')
            ->and($output)->toContain('Location')
            ->and($output)->toMatch('/sensitive-api-keys\.txt:\d+:\d+/');
    });

    it('locates a secret on the line it is actually on', function () {
        $dir = sys_get_temp_dir().'/redactor_scan_'.uniqid();
        mkdir($dir);
        file_put_contents($dir.'/app.env', "APP_NAME=demo\nAPP_ENV=local\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");

        [, $output] = scan(['paths' => [$dir.'/app.env'], '--output' => 'json']);

        $findings = json_decode($output, true)[0]['findings'];

        expect($findings)->not->toBeEmpty()
            ->and($findings[0]['line'])->toBe(3)
            ->and($findings[0]['rule'])->toBe('aws_access_key');

        cleanupDirectory($dir);
    });

    it('shows an excerpt with the secret already redacted', function () {
        $dir = sys_get_temp_dir().'/redactor_scan_'.uniqid();
        mkdir($dir);
        file_put_contents($dir.'/app.env', "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");

        [, $output] = scan(['paths' => [$dir.'/app.env'], '--output' => 'json']);

        $finding = json_decode($output, true)[0]['findings'][0];

        expect($finding['excerpt'])->toContain('AWS_ACCESS_KEY_ID')
            ->and($finding['excerpt'])->toContain('[REDACTED]')
            ->and($finding['excerpt'])->not->toContain('AKIAIOSFODNN7EXAMPLE');

        cleanupDirectory($dir);
    });

    it('reports several findings in one file separately', function () {
        [, $output] = scan(['paths' => [fixture('personal-info.txt')], '--output' => 'json']);

        $findings = json_decode($output, true)[0]['findings'];

        expect(count($findings))->toBeGreaterThan(1)
            ->and(array_unique(array_column($findings, 'rule')))->not->toHaveCount(1);
    });

    it('scans several paths at once', function () {
        [$exitCode, $output] = scan(['paths' => [
            fixture('clean-text-file.txt'),
            fixture('sensitive-api-keys.txt'),
            fixture('personal-info.txt'),
        ]]);

        expect($exitCode)->toBe(0)
            ->and($output)->toContain('Files scanned: 3');
    });

    it('scans a directory', function () {
        [$exitCode, $output] = scan(['paths' => [fixture('subdirectory')]]);

        expect($exitCode)->toBe(0)
            ->and($output)->toContain('Files scanned:');
    });

    it('warns about a path that does not exist', function () {
        [$exitCode, $output] = scan(['paths' => ['/no/such/path.txt']]);

        expect($exitCode)->toBe(0)
            ->and($output)->toContain('Path not found');
    });

    it('honours --summary-only', function () {
        [, $output] = scan([
            'paths' => [fixture('sensitive-api-keys.txt')],
            '--summary-only' => true,
        ]);

        expect($output)->not->toContain('Location')
            ->and($output)->toContain('Total findings:');
    });

    it('honours an explicit --profile', function () {
        [$exitCode, $output] = scan([
            'paths' => [fixture('clean-text-file.txt')],
            '--profile' => 'default',
        ]);

        expect($exitCode)->toBe(0)
            ->and($output)->toContain('profile: default');
    });
});

describe('RedactorScanCommand exit codes', function () {
    beforeEach(function () {
        config(['redactor.scan.profile' => 'file_scan']);
        config(['redactor.scan.baseline' => null]);
    });

    it('exits 0 without --bail even when findings exist', function () {
        [$exitCode] = scan(['paths' => [fixture('sensitive-api-keys.txt')]]);

        expect($exitCode)->toBe(0);
    });

    it('exits 1 with --bail when findings exist', function () {
        [$exitCode] = scan([
            'paths' => [fixture('sensitive-api-keys.txt')],
            '--bail' => true,
        ]);

        expect($exitCode)->toBe(1);
    });

    it('exits 0 with --bail when the file is clean', function () {
        [$exitCode] = scan([
            'paths' => [fixture('clean-text-file.txt')],
            '--bail' => true,
        ]);

        expect($exitCode)->toBe(0);
    });

    it('rejects an unknown output format rather than silently defaulting', function () {
        [$exitCode, $output] = scan([
            'paths' => [fixture('clean-text-file.txt')],
            '--output' => 'yaml',
        ]);

        expect($exitCode)->toBe(1)
            ->and($output)->toContain('Unknown --output format');
    });
});

describe('RedactorScanCommand JSON output', function () {
    beforeEach(function () {
        config(['redactor.scan.profile' => 'file_scan']);
        config(['redactor.scan.baseline' => null]);
    });

    it('emits parseable JSON with no progress chatter', function () {
        [, $output] = scan([
            'paths' => [fixture('sensitive-api-keys.txt')],
            '--output' => 'json',
        ]);

        $decoded = json_decode($output, true);

        expect(json_last_error())->toBe(JSON_ERROR_NONE)
            ->and($decoded)->toBeArray()
            ->and($decoded[0]['status'])->toBe('findings');
    });

    it('gives every finding a rule, position, excerpt and fingerprint', function () {
        [, $output] = scan([
            'paths' => [fixture('sensitive-api-keys.txt')],
            '--output' => 'json',
        ]);

        $finding = json_decode($output, true)[0]['findings'][0];

        expect($finding)->toHaveKeys(['rule', 'line', 'column', 'excerpt', 'profile', 'fingerprint'])
            ->and($finding['line'])->toBeGreaterThan(0)
            ->and($finding['column'])->toBeGreaterThan(0)
            ->and($finding['fingerprint'])->toHaveLength(32);
    });

    it('reports a clean file with an empty findings list', function () {
        [, $output] = scan([
            'paths' => [fixture('clean-text-file.txt')],
            '--output' => 'json',
        ]);

        $decoded = json_decode($output, true);

        expect($decoded[0]['status'])->toBe('clean')
            ->and($decoded[0]['findings'])->toBe([]);
    });
});

describe('RedactorScanCommand SARIF output', function () {
    beforeEach(function () {
        config(['redactor.scan.profile' => 'file_scan']);
        config(['redactor.scan.baseline' => null]);
    });

    it('emits a valid SARIF 2.1.0 document', function () {
        [, $output] = scan([
            'paths' => [fixture('sensitive-api-keys.txt')],
            '--output' => 'sarif',
        ]);

        $sarif = json_decode($output, true);

        expect(json_last_error())->toBe(JSON_ERROR_NONE)
            ->and($sarif['version'])->toBe('2.1.0')
            ->and($sarif['runs'][0]['tool']['driver']['name'])->toBe('Redactor')
            ->and($sarif['runs'][0]['results'])->not->toBeEmpty();
    });

    it('locates each result for GitHub code scanning', function () {
        [, $output] = scan([
            'paths' => [fixture('sensitive-api-keys.txt')],
            '--output' => 'sarif',
        ]);

        $result = json_decode($output, true)['runs'][0]['results'][0];
        $region = $result['locations'][0]['physicalLocation']['region'];

        expect($result['ruleId'])->toBeString()
            ->and($region['startLine'])->toBeGreaterThan(0)
            ->and($region['startColumn'])->toBeGreaterThan(0)
            ->and($result['partialFingerprints'])->toHaveKey('redactorFingerprint/v1');
    });

    it('declares every rule it reports', function () {
        [, $output] = scan([
            'paths' => [fixture('personal-info.txt')],
            '--output' => 'sarif',
        ]);

        $run = json_decode($output, true)['runs'][0];

        $declared = array_column($run['tool']['driver']['rules'], 'id');
        $used = array_unique(array_column($run['results'], 'ruleId'));

        expect(array_diff($used, $declared))->toBe([]);
    });

    it('never puts the secret itself in the report', function () {
        $dir = sys_get_temp_dir().'/redactor_scan_'.uniqid();
        mkdir($dir);
        file_put_contents($dir.'/app.env', "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");

        [, $output] = scan(['paths' => [$dir.'/app.env'], '--output' => 'sarif']);

        // A SARIF file gets uploaded to GitHub; publishing the secret in it
        // would be worse than not scanning at all.
        expect($output)->not->toContain('AKIAIOSFODNN7EXAMPLE');

        cleanupDirectory($dir);
    });
});

describe('RedactorScanCommand baseline', function () {
    beforeEach(function () {
        config(['redactor.scan.profile' => 'file_scan']);

        $this->baseline = sys_get_temp_dir().'/redactor_baseline_'.uniqid().'.json';
        config(['redactor.scan.baseline' => $this->baseline]);
    });

    afterEach(function () {
        if (is_file($this->baseline)) {
            unlink($this->baseline);
        }
    });

    it('writes accepted findings and exits 0', function () {
        [$exitCode, $output] = scan([
            'paths' => [fixture('sensitive-api-keys.txt')],
            '--update-baseline' => true,
        ]);

        expect($exitCode)->toBe(0)
            ->and($output)->toContain('Wrote')
            ->and(is_file($this->baseline))->toBeTrue();

        $decoded = json_decode((string) file_get_contents($this->baseline), true);

        expect($decoded['version'])->toBe(1)
            ->and($decoded['findings'])->not->toBeEmpty()
            ->and($decoded['findings'][0])->toHaveKeys(['fingerprint', 'rule', 'path']);
    });

    it('suppresses baselined findings on the next run', function () {
        scan(['paths' => [fixture('sensitive-api-keys.txt')], '--update-baseline' => true]);

        [$exitCode, $output] = scan([
            'paths' => [fixture('sensitive-api-keys.txt')],
            '--bail' => true,
        ]);

        // Without a baseline a repo with fixtures or a documented example key
        // can never go green, which is how a scanner gets switched off.
        expect($exitCode)->toBe(0)
            ->and($output)->toContain('Total findings: 0')
            ->and($output)->toContain('Suppressed by baseline:');
    });

    it('still fails on a finding the baseline does not cover', function () {
        scan(['paths' => [fixture('clean-text-file.txt')], '--update-baseline' => true]);

        [$exitCode] = scan([
            'paths' => [fixture('sensitive-api-keys.txt')],
            '--bail' => true,
        ]);

        expect($exitCode)->toBe(1);
    });

    it('never writes the secret into the baseline file', function () {
        $dir = sys_get_temp_dir().'/redactor_scan_'.uniqid();
        mkdir($dir);
        file_put_contents($dir.'/app.env', "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");

        scan(['paths' => [$dir.'/app.env'], '--update-baseline' => true]);

        expect(file_get_contents($this->baseline))->not->toContain('AKIAIOSFODNN7EXAMPLE');

        cleanupDirectory($dir);
    });

    it('reports a malformed baseline instead of ignoring it', function () {
        file_put_contents($this->baseline, '{"nope": true}');

        [$exitCode, $output] = scan(['paths' => [fixture('clean-text-file.txt')]]);

        expect($exitCode)->toBe(1)
            ->and($output)->toContain('findings');
    });

    it('treats a missing baseline file as empty', function () {
        [$exitCode] = scan(['paths' => [fixture('clean-text-file.txt')]]);

        expect($exitCode)->toBe(0);
    });

    it('refuses --update-baseline with nowhere to write', function () {
        config(['redactor.scan.baseline' => null]);

        [$exitCode, $output] = scan([
            'paths' => [fixture('clean-text-file.txt')],
            '--update-baseline' => true,
        ]);

        expect($exitCode)->toBe(1)
            ->and($output)->toContain('--update-baseline needs a path');
    });
});

describe('Baseline fingerprints', function () {
    it('survives the finding moving to a different line', function () {
        $first = ScanFinding::fingerprint('aws', 'a.env', 'AKIA123');
        $second = ScanFinding::fingerprint('aws', 'a.env', 'AKIA123');

        expect($first)->toBe($second);
    });

    it('differs per rule, per path and per secret', function () {
        $base = ScanFinding::fingerprint('aws', 'a.env', 'AKIA123');

        expect(ScanFinding::fingerprint('gh', 'a.env', 'AKIA123'))->not->toBe($base)
            ->and(ScanFinding::fingerprint('aws', 'b.env', 'AKIA123'))->not->toBe($base)
            ->and(ScanFinding::fingerprint('aws', 'a.env', 'AKIA999'))->not->toBe($base);
    });

    it('accepts a plain list of fingerprints as well as objects', function () {
        $path = sys_get_temp_dir().'/redactor_baseline_'.uniqid().'.json';
        file_put_contents($path, json_encode(['findings' => ['abc123', ['fingerprint' => 'def456']]]));

        $baseline = Baseline::load($path);

        expect($baseline->fingerprints)->toHaveKeys(['abc123', 'def456']);

        unlink($path);
    });
});
