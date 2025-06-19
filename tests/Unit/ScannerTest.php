<?php

use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Scanner\Scanner;
use Mockery;

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

    it('detects full content redaction when sensitive patterns are found', function () {
        $redactor = resolve(Redactor::class);
        $scanner = new Scanner($redactor);

        // Create content with sensitive information - this will get fully redacted
        $sensitiveFile = $this->tempDir.'/sensitive.txt';
        $content = "This is a log file.\nContact: john@example.com\nEnd of log.";

        file_put_contents($sensitiveFile, $content);

        $result = $scanner->scanFile($sensitiveFile, 'file_scan');

        expect($result->skipped)->toBeFalse();
        expect($result->error)->toBeNull();
        expect($result->hasFindings())->toBeTrue();
        expect($result->findings)->toHaveCount(1);

        $finding = $result->findings[0];
        expect($finding['type'])->toBe('full_content_redacted');
        expect($finding['reason'])->toBe('Entire content was redacted');
        expect($finding['original_length'])->toBe(strlen($content));
        expect($finding['profile'])->toBe('file_scan');
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

    it('handles array-based redaction with _redacted_keys', function () {
        // Mock the Redactor to return array with _redacted metadata
        $mockRedactor = Mockery::mock(Redactor::class);
        $mockRedactor->shouldReceive('redact')
            ->once()
            ->andReturn([
                'user' => 'john',
                'email' => '[REDACTED]',
                'api_key' => '[REDACTED]',
                '_redacted' => true,
                '_redacted_keys' => [
                    [
                        'key' => 'email',
                        'type' => 'blocked_key',
                        'strategy' => 'BlockedKeysStrategy',
                    ],
                    [
                        'key' => 'api_key',
                        'type' => 'blocked_key',
                        'strategy' => 'BlockedKeysStrategy',
                    ],
                ],
            ]);

        $scanner = new Scanner($mockRedactor);

        $testFile = $this->tempDir.'/mock_test.json';
        file_put_contents($testFile, '{"user":"john","email":"test@example.com","api_key":"secret123"}');

        $result = $scanner->scanFile($testFile, 'default');

        expect($result->skipped)->toBeFalse();
        expect($result->error)->toBeNull();
        expect($result->hasFindings())->toBeTrue();
        expect($result->findings)->toHaveCount(2);
        expect($result->findings[0]['key'])->toBe('email');
        expect($result->findings[0]['type'])->toBe('blocked_key');
        expect($result->findings[1]['key'])->toBe('api_key');
        expect($result->findings[1]['type'])->toBe('blocked_key');
        expect($result->profile)->toBe('default');
    });

});

/**
 * Clean up directory recursively
 */
function cleanupDirectory(string $dir): void
{
    if (! is_dir($dir)) {
        return;
    }

    $files = scandir($dir);
    foreach ($files as $file) {
        if ($file === '.' || $file === '..') {
            continue;
        }

        $path = $dir.'/'.$file;

        if (is_dir($path)) {
            cleanupDirectory($path);
        } else {
            // Ensure file is writable before deletion
            chmod($path, 0644);
            unlink($path);
        }
    }

    rmdir($dir);
}
