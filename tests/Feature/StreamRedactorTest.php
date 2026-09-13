<?php

declare(strict_types=1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Route;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Streaming\StreamRedactor;

function streamed(iterable $chunks, int $holdback = 32): array
{
    $stream = new StreamRedactor(app(Redactor::class), 'file_scan', $holdback);
    $emitted = [];

    foreach ($chunks as $chunk) {
        $emitted[] = $stream->push($chunk);
    }

    $emitted[] = $stream->flush();

    return $emitted;
}

describe('StreamRedactor', function () {
    it('catches a secret split across two chunks', function () {
        $text = "log line one\nthe key is sk_live_4eC39HqLyjWDarjtT1zdp7dc ok\nline three\n";
        $split = strpos($text, 'sk_live_') + 12; // mid-token

        $emitted = streamed([substr($text, 0, $split), substr($text, $split)], 16);

        expect(implode('', $emitted))->toBe(app(Redactor::class)->redact($text, 'file_scan'))
            ->and(implode('', $emitted))->not->toContain('4eC39HqLyjWDarjtT1zdp7dc');
    });

    it('produces the same output as a whole-string redaction however the chunks fall', function () {
        $text = str_repeat("user bob@example.com paid with 4111111111111111 on 2026-09-13\n", 40);
        $whole = app(Redactor::class)->redact($text, 'file_scan');

        foreach ([1, 7, 64, 1000] as $size) {
            expect(implode('', streamed(str_split($text, $size), 48)))->toBe($whole, "chunk size {$size}");
        }
    });

    it('never emits anything that a later chunk could have completed', function () {
        $stream = new StreamRedactor(app(Redactor::class), 'file_scan', 20);

        $first = $stream->push('hello sk_live_4eC39Hq');

        expect($first)->toBe('');

        $second = $stream->push("LyjWDarjtT1zdp7dc bye\nmore text to push the window along\n");

        expect($first.$second.$stream->flush())->not->toContain('4eC39');
    });

    it('holds an open PEM block whole', function () {
        $pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nMIIEowIBAAKCAQEB\nMIIEowIBAAKCAQEC\n-----END RSA PRIVATE KEY-----\n";
        $text = "header line here to fill the buffer\n".$pem."trailer\n";

        $out = implode('', streamed(str_split($text, 10), 24));

        expect($out)->not->toContain('MIIEowIBAAKCAQEA')
            ->and($out)->toContain('header line')
            ->and($out)->toContain('trailer');
    });

    it('streams through a generator', function () {
        $stream = new StreamRedactor(app(Redactor::class), 'file_scan', 8);

        $out = implode('', iterator_to_array($stream->through(['mail bob@ex', 'ample.com now and ', 'that is all'])));

        expect($out)->toBe('mail [REDACTED] now and that is all');
    });

    it('keeps memory bounded by the hold-back, not the stream', function () {
        $stream = new StreamRedactor(app(Redactor::class), 'file_scan', 64);
        $chunk = str_repeat("plain words only here\n", 10);

        memory_reset_peak_usage();
        $before = memory_get_peak_usage();

        for ($i = 0; $i < 2000; $i++) {
            $stream->push($chunk);
        }

        expect(memory_get_peak_usage() - $before)->toBeLessThan(2 * 1024 * 1024);
    });

    it('wraps an echoing callback and redacts what it echoes', function () {
        $stream = new StreamRedactor(app(Redactor::class), 'file_scan', 16);

        $wrapped = $stream->wrap(function () {
            echo 'first bob@exam';
            echo "ple.com second\n";
            echo 'AKIAIOSFODNN7EXAMPLE end';
        }, 8);

        ob_start();
        $wrapped();
        $out = ob_get_clean();

        expect($out)->toBe("first [REDACTED] second\n[REDACTED] end");
    });
});

describe('Streamed responses through the redact middleware', function () {
    it('redacts a streamed response as it streams', function () {
        Route::get('/stream', fn () => response()->stream(function () {
            echo "event: message\ndata: contact bob@exam";
            echo "ple.com and token sk_live_4eC39HqLyjWDarjtT1zdp7dc\n\n";
        }, 200, ['Content-Type' => 'text/event-stream']))->middleware('redact:file_scan');

        $response = $this->get('/stream');

        $response->assertOk();
        $content = $response->streamedContent();

        expect($content)->toContain('data: contact [REDACTED] and token [REDACTED]')
            ->and($content)->not->toContain('bob@example.com');
    });
});
