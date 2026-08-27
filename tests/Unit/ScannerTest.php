<?php

use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Scanner\Scanner;

describe('Scanner', function () {
    beforeEach(function () {
        $this->tempDir = sys_get_temp_dir().'/scanner_test_'.uniqid();
        mkdir($this->tempDir, 0755, true);
    });

    afterEach(function () {
        cleanupDirectory($this->tempDir);
    });

    it('handles unreadable files gracefully when called directly', function () {
        $redactor = resolve(Redactor::class);
        $scanner = new Scanner($redactor);

        // Create an unreadable file
        $unreadableFile = $this->tempDir.'/unreadable.txt';
        file_put_contents($unreadableFile, 'secret content');
        chmod($unreadableFile, 0000);

        $result = $scanner->scanFile($unreadableFile);

        expect($result->skipped)->toBeTrue();
        expect($result->error)->toBe('File unreadable');
        expect($result->findings)->toBeEmpty();
        expect($result->path)->toBe($unreadableFile);

        // Restore permissions for cleanup
        chmod($unreadableFile, 0644);
    });

    it('handles non-existent files gracefully when called directly', function () {
        $redactor = resolve(Redactor::class);
        $scanner = new Scanner($redactor);

        $nonExistentFile = $this->tempDir.'/does-not-exist.txt';

        $result = $scanner->scanFile($nonExistentFile);

        expect($result->skipped)->toBeTrue();
        expect($result->error)->toBe('File unreadable');
        expect($result->findings)->toBeEmpty();
        expect($result->path)->toBe($nonExistentFile);
    });

    it('scans readable files successfully when called directly', function () {
        $redactor = resolve(Redactor::class);
        $scanner = new Scanner($redactor);

        // Create a readable file with sensitive content that matches our patterns
        $readableFile = $this->tempDir.'/readable.txt';
        file_put_contents($readableFile, 'Email: john@example.com and API Key: sk_test_1234567890abcdef1234567890abcdef');

        $result = $scanner->scanFile($readableFile, 'file_scan');

        expect($result->skipped)->toBeFalse();
        expect($result->error)->toBeNull();
        expect($result->hasFindings())->toBeTrue();
        expect($result->path)->toBe($readableFile);
        expect($result->profile)->toBe('file_scan');
    });

    it('reports a located finding for each sensitive span', function () {
        $redactor = resolve(Redactor::class);
        $scanner = new Scanner($redactor);

        // Create content with sensitive information - the address is replaced,
        // the surrounding log lines survive.
        $sensitiveFile = $this->tempDir.'/sensitive.txt';
        $content = "This is a log file.\nContact: john@example.com\nEnd of log.";

        file_put_contents($sensitiveFile, $content);

        $result = $scanner->scanFile($sensitiveFile, 'file_scan');

        expect($result->skipped)->toBeFalse();
        expect($result->error)->toBeNull();
        expect($result->hasFindings())->toBeTrue();
        expect($result->findings)->toHaveCount(1);

        $finding = $result->findings[0];
        expect($finding->rule)->toBe('email');
        expect($finding->line)->toBe(2);
        expect($finding->column)->toBe(10);
        expect($finding->excerpt)->toBe('Contact: [REDACTED]');
        expect($finding->excerpt)->not->toContain('john@example.com');
        expect($finding->profile)->toBe('file_scan');
        expect($finding->fingerprint)->toHaveLength(32);
    });

    it('detects array-based redaction for structured data', function () {
        $redactor = resolve(Redactor::class);
        $scanner = new Scanner($redactor);

        // Create JSON file with sensitive data that will trigger array-based redaction
        $jsonFile = $this->tempDir.'/data.json';
        $jsonContent = json_encode([
            'user' => 'john',
            'email' => 'john@example.com',
            'api_key' => 'sk_test_1234567890abcdef1234567890abcdef',
            'config' => [
                'debug' => true,
                'database_password' => 'supersecret123',
            ],
        ], JSON_PRETTY_PRINT);

        file_put_contents($jsonFile, $jsonContent);

        // Use a profile that includes key-based strategies for structured data
        $result = $scanner->scanFile($jsonFile, 'default');

        expect($result->skipped)->toBeFalse();
        expect($result->error)->toBeNull();
        expect($result->hasFindings())->toBeTrue();
        expect($result->findings)->toBeArray();
        expect($result->profile)->toBe('default');

        // Should have detected redacted keys from the structured data
        expect(count($result->findings))->toBeGreaterThan(0);
    });

    it('reports the key alongside a key-based finding in structured data', function () {
        $scanner = new Scanner(resolve(Redactor::class));

        $testFile = $this->tempDir.'/keys.json';
        file_put_contents($testFile, "{\n  \"user\": \"john\",\n  \"password\": \"supersecret123\"\n}");

        $result = $scanner->scanFile($testFile, 'file_scan');

        expect($result->hasFindings())->toBeTrue();

        $rules = array_map(fn ($finding) => $finding->rule, $result->findings);
        expect($rules)->toContain('password_assignment');
    });

    it('reports paths relative to a base when given one', function () {
        $scanner = new Scanner(resolve(Redactor::class));

        $file = $this->tempDir.'/nested/app.env';
        mkdir(dirname($file), 0777, true);
        file_put_contents($file, "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");

        $result = $scanner->scanFile($file, 'file_scan', $this->tempDir);

        expect($result->findings[0]->path)->toBe('nested/app.env')
            // The absolute path stays on the result for the caller that needs it.
            ->and($result->path)->toBe($file);
    });

    it('returns no findings for clean content', function () {
        $scanner = new Scanner(resolve(Redactor::class));

        $file = $this->tempDir.'/clean.txt';
        file_put_contents($file, "nothing to see here\njust ordinary prose\n");

        $result = $scanner->scanFile($file, 'file_scan');

        expect($result->hasFindings())->toBeFalse()
            ->and($result->findings)->toBe([]);
    });

    it('numbers lines correctly in a multi-line file', function () {
        $scanner = new Scanner(resolve(Redactor::class));

        $file = $this->tempDir.'/multi.env';
        file_put_contents($file, implode("\n", [
            'FIRST=ok',
            'SECOND=ok',
            'THIRD=ok',
            'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
            'FIFTH=ok',
        ]));

        $result = $scanner->scanFile($file, 'file_scan');

        $aws = array_values(array_filter(
            $result->findings,
            fn ($finding) => $finding->rule === 'aws_access_key'
        ));

        expect($aws)->toHaveCount(1)
            ->and($aws[0]->line)->toBe(4);
    });

});
