<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Scanner\LineWindowReader;
use Kirschbaum\Redactor\Scanner\Scanner;
use Kirschbaum\Redactor\Scanner\ScanResult;

function scratchFile(string $contents, string $name = 'scan.txt'): string
{
    $dir = sys_get_temp_dir().'/redactor_stream_'.uniqid();
    mkdir($dir);
    $path = $dir.'/'.$name;
    file_put_contents($path, $contents);

    return $path;
}

describe('Line window reader', function () {
    it('covers every line exactly once when nothing overlaps', function () {
        $path = scratchFile(implode("\n", array_map(fn (int $i) => "line {$i}", range(1, 10))));

        $reader = new LineWindowReader($path, windowLines: 4, overlapLines: 0);

        $seen = [];
        foreach ($reader as [$start, $text]) {
            foreach (explode("\n", $text) as $offset => $line) {
                $seen[$start + $offset] = $line;
            }
        }

        expect($seen)->toHaveCount(10)
            ->and($seen[1])->toBe('line 1')
            ->and($seen[10])->toBe('line 10');

        cleanupDirectory(dirname($path));
    });

    it('numbers lines correctly across windows with overlap', function () {
        $path = scratchFile(implode("\n", array_map(fn (int $i) => "line {$i}", range(1, 20))));

        foreach (new LineWindowReader($path, windowLines: 6, overlapLines: 2) as [$start, $text]) {
            $first = explode("\n", $text)[0];

            // The reported start line must actually be the first line of the
            // window, or every finding in it is attributed to the wrong place.
            expect($first)->toBe("line {$start}");
        }

        cleanupDirectory(dirname($path));
    });

    it('carries lines forward so a match spanning a boundary survives', function () {
        $path = scratchFile(implode("\n", array_map(fn (int $i) => "line {$i}", range(1, 12))));

        $windows = [];
        foreach (new LineWindowReader($path, windowLines: 5, overlapLines: 2) as [$start, $text]) {
            $windows[] = [$start, $text];
        }

        expect(count($windows))->toBeGreaterThan(1)
            // Window two begins inside window one.
            ->and($windows[1][0])->toBeLessThan($windows[0][0] + 5);

        cleanupDirectory(dirname($path));
    });

    it('never stalls when the overlap is set as large as the window', function () {
        $path = scratchFile(implode("\n", array_map(fn (int $i) => "line {$i}", range(1, 30))));

        $count = 0;
        foreach (new LineWindowReader($path, windowLines: 4, overlapLines: 99) as $ignored) {
            $count++;
            if ($count > 100) {
                break;
            }
        }

        expect($count)->toBeLessThan(100);

        cleanupDirectory(dirname($path));
    });

    it('yields nothing for an unreadable file rather than throwing', function () {
        $reader = new LineWindowReader('/no/such/file');

        expect(iterator_to_array($reader))->toBe([]);
    });

    it('handles a file with no trailing newline', function () {
        $path = scratchFile('only line, no newline');

        $windows = iterator_to_array(new LineWindowReader($path, windowLines: 10));

        expect($windows)->toHaveCount(1)
            ->and($windows[0][1])->toBe('only line, no newline');

        cleanupDirectory(dirname($path));
    });
});

describe('Streaming scan correctness', function () {
    it('reports the same findings as a single-window scan', function () {
        $lines = array_map(fn (int $i) => "line {$i} ordinary text", range(1, 60));
        $lines[9] = 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE';
        $lines[39] = 'contact bob@example.com';

        $path = scratchFile(implode("\n", $lines));

        $wide = (new Scanner(app(Redactor::class), windowLines: 10_000))->scanFile($path, 'file_scan');
        $narrow = (new Scanner(app(Redactor::class), windowLines: 7, overlapLines: 3))->scanFile($path, 'file_scan');

        $shape = fn (ScanResult $result) => array_map(
            fn ($f) => $f->rule.'@'.$f->line,
            $result->findings
        );

        // Windowing must not change what is found or where.
        expect($shape($narrow))->toBe($shape($wide))
            ->and($shape($wide))->not->toBeEmpty();

        cleanupDirectory(dirname($path));
    });

    it('numbers a finding by its absolute line, not its line within a window', function () {
        $lines = array_map(fn (int $i) => "filler {$i}", range(1, 100));
        $lines[74] = 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE';

        $path = scratchFile(implode("\n", $lines));

        $result = (new Scanner(app(Redactor::class), windowLines: 8, overlapLines: 2))->scanFile($path, 'file_scan');

        $aws = array_values(array_filter($result->findings, fn ($f) => $f->rule === 'aws_access_key'));

        expect($aws)->toHaveCount(1)
            ->and($aws[0]->line)->toBe(75);

        cleanupDirectory(dirname($path));
    });

    it('reports a finding in the overlap region only once', function () {
        $lines = array_map(fn (int $i) => "filler {$i}", range(1, 20));
        // Line 5 sits inside the overlap of the first two windows.
        $lines[4] = 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE';

        $path = scratchFile(implode("\n", $lines));

        $result = (new Scanner(app(Redactor::class), windowLines: 6, overlapLines: 4))->scanFile($path, 'file_scan');

        $aws = array_filter($result->findings, fn ($f) => $f->rule === 'aws_access_key');

        expect($aws)->toHaveCount(1);

        cleanupDirectory(dirname($path));
    });

    it('returns findings in file order', function () {
        $lines = array_map(fn (int $i) => "filler {$i}", range(1, 40));
        $lines[4] = 'first bob@example.com';
        $lines[24] = 'later AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE';

        $path = scratchFile(implode("\n", $lines));

        $result = (new Scanner(app(Redactor::class), windowLines: 6, overlapLines: 2))->scanFile($path, 'file_scan');

        $lineNumbers = array_map(fn ($f) => $f->line, $result->findings);
        $sorted = $lineNumbers;
        sort($sorted);

        expect($lineNumbers)->toBe($sorted);

        cleanupDirectory(dirname($path));
    });

    it('still reports an unreadable file as skipped', function () {
        $result = (new Scanner(app(Redactor::class)))->scanFile('/no/such/file', 'file_scan');

        expect($result->skipped)->toBeTrue()
            ->and($result->error)->toBe('File unreadable');
    });

    it('finds nothing in a clean file', function () {
        $path = scratchFile("nothing to see here\njust ordinary prose\nand more of it\n");

        expect((new Scanner(app(Redactor::class)))->scanFile($path, 'file_scan')->hasFindings())->toBeFalse();

        cleanupDirectory(dirname($path));
    });
});

describe('Streaming memory', function () {
    it('holds memory flat as the file grows', function () {
        // A 12 MB file scanned in windows should not cost anything like 12 MB.
        $dir = sys_get_temp_dir().'/redactor_big_'.uniqid();
        mkdir($dir);
        $path = $dir.'/big.log';

        $handle = fopen($path, 'wb');
        $line = str_repeat('ordinary log content that is not sensitive ', 4)."\n";
        for ($i = 0; $i < 60_000; $i++) {
            fwrite($handle, $line);
        }
        fwrite($handle, "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
        fclose($handle);

        expect(filesize($path))->toBeGreaterThan(10_000_000);

        gc_collect_cycles();
        $before = memory_get_usage();

        $result = (new Scanner(app(Redactor::class)))->scanFile($path, 'file_scan');

        $growthMb = (memory_get_usage() - $before) / 1_048_576;

        expect($result->hasFindings())->toBeTrue()
            // Loading the file whole would be 12 MB before any redaction.
            ->and($growthMb)->toBeLessThan(6.0);

        cleanupDirectory($dir);
    });
});
