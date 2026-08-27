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
        fn (string $f) => ltrim(str_replace((string) $real, '', $f), '/'),
        $files
    );

    sort($relative);

    return $relative;
}

describe('FileCollector exclusions', function () {
    it('excludes directories named by a path pattern', function () {
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

    it('excludes nested files under an excluded directory', function () {
        $base = tree([
            'keep.php' => 'ok',
            'vendor/a/b/c/deep.php' => 'x',
        ]);

        expect(collected($base, ['vendor/*']))->toBe(['keep.php']);

        cleanupDirectory($base);
    });

    it('still excludes by basename glob', function () {
        $base = tree([
            'composer.lock' => 'x',
            'app.min.js' => 'x',
            'sub/other.lock' => 'x',
            'keep.php' => 'ok',
        ]);

        expect(collected($base, ['*.lock', '*.min.js']))->toBe(['keep.php']);

        cleanupDirectory($base);
    });

    it('collects everything when no patterns are given', function () {
        $base = tree(['a.php' => 'x', 'sub/b.php' => 'x']);

        expect(collected($base))->toBe(['a.php', 'sub/b.php']);

        cleanupDirectory($base);
    });

    it('ignores an empty pattern rather than excluding everything', function () {
        $base = tree(['a.php' => 'x']);

        expect(collected($base, ['']))->toBe(['a.php']);

        cleanupDirectory($base);
    });

    it('scans a file named explicitly even when a pattern would exclude it', function () {
        $base = tree(['vendor/pkg/a.php' => 'x']);

        $files = FileCollector::collect([$base.'/vendor/pkg/a.php'], ['vendor/*']);

        expect($files)->toHaveCount(1);

        cleanupDirectory($base);
    });
});

describe('FileCollector eligibility', function () {
    it('skips files over the size limit', function () {
        $base = tree([
            'small.txt' => str_repeat('a', 10),
            'big.txt' => str_repeat('a', 5000),
        ]);

        expect(collected($base, [], 1000))->toBe(['small.txt']);

        cleanupDirectory($base);
    });

    it('skips binary files', function () {
        // Random bytes score high entropy, so every binary in the tree used to
        // come back as a finding.
        $base = tree([
            'text.txt' => "hello\nworld\n",
            'image.bin' => "\x89PNG\r\n\x1a\n".random_bytes(512),
        ]);

        expect(collected($base))->toBe(['text.txt']);

        cleanupDirectory($base);
    });

    it('keeps binary files when skip_binary is off', function () {
        $base = tree([
            'text.txt' => 'hello',
            'image.bin' => "\x00\x01\x02\x03",
        ]);

        expect(collected($base, [], 10_485_760, false))->toBe(['image.bin', 'text.txt']);

        cleanupDirectory($base);
    });

    it('keeps UTF-8 text that is not ASCII', function () {
        $base = tree([
            'japanese.txt' => '日本語のテキストです',
            'accents.txt' => 'café naïve',
        ]);

        expect(collected($base))->toBe(['accents.txt', 'japanese.txt']);

        cleanupDirectory($base);
    });

    it('keeps an empty file', function () {
        $base = tree(['empty.txt' => '']);

        expect(collected($base))->toBe(['empty.txt']);

        cleanupDirectory($base);
    });

    it('skips unreadable files', function () {
        $base = tree(['secret.txt' => 'x', 'open.txt' => 'y']);
        chmod($base.'/secret.txt', 0000);

        expect(collected($base))->toBe(['open.txt']);

        cleanupDirectory($base);
    })->skip(posix_geteuid() === 0, 'chmod does not restrict root');

    it('silently ignores paths that do not exist', function () {
        expect(FileCollector::collect(['/no/such/path/at/all']))->toBe([]);
    });

    it('deduplicates a file reached by two paths', function () {
        $base = tree(['a.php' => 'x']);

        expect(FileCollector::collect([$base, $base.'/a.php']))->toHaveCount(1);

        cleanupDirectory($base);
    });
});

describe('FileCollector gitignore awareness', function () {
    it('skips files git is ignoring', function () {
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

    it('includes them when respect_gitignore is off', function () {
        $base = tree([
            '.gitignore' => "ignored.txt\n",
            'ignored.txt' => 'x',
        ]);

        exec('git -C '.escapeshellarg($base).' init -q 2>/dev/null');

        expect(collected($base, [], 10_485_760, true, false))->toContain('ignored.txt');

        cleanupDirectory($base);
    });
});
