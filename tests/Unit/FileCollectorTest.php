<?php

declare(strict_types=1);

use Kirschbaum\Redactor\Scanner\FileCollector;

function tree(array $files): string
{
    $base = sys_get_temp_dir().'/redactor_fc_'.uniqid();

    foreach ($files as $path => $contents) {
        $full = $base.'/'.$path;
        @mkdir(dirname($full), 0777, true);
        file_put_contents($full, $contents);
    }

    return $base;
}

/** @return array<int, string> relative paths, sorted */
function collected(string $base, array $patterns = [], int $max = 10_485_760, bool $skipBinary = true, bool $gitignore = true): array
{
    $files = FileCollector::collect([$base], $patterns, $max, $skipBinary, $gitignore);

    $real = realpath($base);
    $relative = array_map(
        fn (string $f): string => ltrim(str_replace((string) $real, '', $f), '/'),
        $files
    );

    sort($relative);

    return $relative;
}

describe('FileCollector exclusions', function (): void {
    it('excludes directories named by a path pattern', function (): void {
        // notName() compares basenames only, so the shipped 'vendor/*' and
        // 'node_modules/*' defaults could never match and every dependency in
        // the project was scanned.
        $base = tree([
            'app.php' => 'ok',
            'vendor/pkg/a.php' => 'secret@leak.com',
            'node_modules/x/b.js' => 'secret@leak.com',
        ]);

        expect(collected($base, ['vendor/*', 'node_modules/*']))->toBe(['app.php']);

        cleanupDirectory($base);
    });

    it('excludes nested files under an excluded directory', function (): void {
        $base = tree([
            'keep.php' => 'ok',
            'vendor/a/b/c/deep.php' => 'x',
        ]);

        expect(collected($base, ['vendor/*']))->toBe(['keep.php']);

        cleanupDirectory($base);
    });

    it('still excludes by basename glob', function (): void {
        $base = tree([
            'composer.lock' => 'x',
            'app.min.js' => 'x',
            'sub/other.lock' => 'x',
            'keep.php' => 'ok',
        ]);

        expect(collected($base, ['*.lock', '*.min.js']))->toBe(['keep.php']);

        cleanupDirectory($base);
    });

    it('collects everything when no patterns are given', function (): void {
        $base = tree(['a.php' => 'x', 'sub/b.php' => 'x']);

        expect(collected($base))->toBe(['a.php', 'sub/b.php']);

        cleanupDirectory($base);
    });

    it('ignores an empty pattern rather than excluding everything', function (): void {
        $base = tree(['a.php' => 'x']);

        expect(collected($base, ['']))->toBe(['a.php']);

        cleanupDirectory($base);
    });

    it('scans a file named explicitly even when a pattern would exclude it', function (): void {
        $base = tree(['vendor/pkg/a.php' => 'x']);

        $files = FileCollector::collect([$base.'/vendor/pkg/a.php'], ['vendor/*']);

        expect($files)->toHaveCount(1);

        cleanupDirectory($base);
    });
});

describe('FileCollector eligibility', function (): void {
    it('skips files over the size limit', function (): void {
        $base = tree([
            'small.txt' => str_repeat('a', 10),
            'big.txt' => str_repeat('a', 5000),
        ]);

        expect(collected($base, [], 1000))->toBe(['small.txt']);

        cleanupDirectory($base);
    });

    it('skips binary files', function (): void {
        // Random bytes score high entropy, so every binary in the tree used to
        // come back as a finding.
        $base = tree([
            'text.txt' => "hello\nworld\n",
            'image.bin' => "\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR".random_bytes(512),
        ]);

        expect(collected($base))->toBe(['text.txt']);

        cleanupDirectory($base);
    });

    it('keeps binary files when skip_binary is off', function (): void {
        $base = tree([
            'text.txt' => 'hello',
            'image.bin' => "\x00\x01\x02\x03",
        ]);

        expect(collected($base, [], 10_485_760, false))->toBe(['image.bin', 'text.txt']);

        cleanupDirectory($base);
    });

    it('keeps text in a legacy encoding, which is not binary', function (): void {
        $base = tree(['latin1.txt' => "caf\xe9 cr\xe8me br\xfbl\xe9e\n".str_repeat("R\xe9sum\xe9 de la r\xe9union\n", 40)]);

        expect(collected($base))->toHaveCount(1);
    });

    it('skips NUL-free binary by its control bytes', function (): void {
        $bytes = '';
        for ($i = 1; $i < 256; $i++) {
            $bytes .= chr($i);
        }

        $base = tree(['blob.bin' => str_repeat($bytes, 8)]);

        expect(collected($base))->toHaveCount(0);
    });

    it('keeps UTF-8 text that is not ASCII', function (): void {
        $base = tree([
            'japanese.txt' => '日本語のテキストです',
            'accents.txt' => 'café naïve',
        ]);

        expect(collected($base))->toBe(['accents.txt', 'japanese.txt']);

        cleanupDirectory($base);
    });

    it('keeps an empty file', function (): void {
        $base = tree(['empty.txt' => '']);

        expect(collected($base))->toBe(['empty.txt']);

        cleanupDirectory($base);
    });

    it('skips unreadable files', function (): void {
        $base = tree(['secret.txt' => 'x', 'open.txt' => 'y']);
        chmod($base.'/secret.txt', 0000);

        expect(collected($base))->toBe(['open.txt']);

        cleanupDirectory($base);
    })->skip(posix_geteuid() === 0, 'chmod does not restrict root');

    it('silently ignores paths that do not exist', function (): void {
        expect(FileCollector::collect(['/no/such/path/at/all']))->toBe([]);
    });

    it('deduplicates a file reached by two paths', function (): void {
        $base = tree(['a.php' => 'x']);

        expect(FileCollector::collect([$base, $base.'/a.php']))->toHaveCount(1);

        cleanupDirectory($base);
    });
});

describe('FileCollector gitignore awareness', function (): void {
    it('skips files git is ignoring', function (): void {
        $base = tree([
            '.gitignore' => "ignored.txt\n",
            'ignored.txt' => 'x',
            'kept.txt' => 'y',
        ]);

        exec('git -C '.escapeshellarg($base).' init -q 2>/dev/null');

        expect(collected($base))->not->toContain('ignored.txt')
            ->and(collected($base))->toContain('kept.txt');

        cleanupDirectory($base);
    });

    it('includes them when respect_gitignore is off', function (): void {
        $base = tree([
            '.gitignore' => "ignored.txt\n",
            'ignored.txt' => 'x',
        ]);

        exec('git -C '.escapeshellarg($base).' init -q 2>/dev/null');

        expect(collected($base, [], 10_485_760, true, false))->toContain('ignored.txt');

        cleanupDirectory($base);
    });
});

describe('FileCollector binary sniffing', function (): void {
    it('skips content that is not valid UTF-8 even when it has no NUL byte', function (): void {
        $base = tree([
            'blob.bin' => str_repeat("\x80\x81\x82\x83\x84\x85\x86\x87", 64),
            'text.txt' => 'ok',
        ]);

        expect(collected($base))->toBe(['text.txt']);

        cleanupDirectory($base);
    });
});
