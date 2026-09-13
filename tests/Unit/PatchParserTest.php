<?php

declare(strict_types=1);

use Kirschbaum\Redactor\Scanner\Git\Patch;
use Kirschbaum\Redactor\Scanner\Git\PatchParser;

describe('PatchParser', function (): void {
    it('collects added lines with their real line numbers', function (): void {
        $diff = <<<'DIFF'
diff --git a/config/app.php b/config/app.php
index 1111111..2222222 100644
--- a/config/app.php
+++ b/config/app.php
@@ -10,0 +11,2 @@
+    'key' => 'AKIAIOSFODNN7EXAMPLE',
+    'other' => 'x',
@@ -40 +42 @@
-    'old' => 1,
+    'new' => 2,
DIFF;

        $patches = PatchParser::parse($diff);

        expect($patches)->toHaveCount(1)
            ->and($patches[0]->path)->toBe('config/app.php')
            ->and($patches[0]->addedLines)->toBe([
                11 => "    'key' => 'AKIAIOSFODNN7EXAMPLE',",
                12 => "    'other' => 'x',",
                42 => "    'new' => 2,",
            ])
            ->and($patches[0]->lineAt(3))->toBe(42);
    });

    it('splits several files and skips deletions and binaries', function (): void {
        $diff = <<<'DIFF'
diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -0,0 +1 @@
+alpha
diff --git a/gone.txt b/gone.txt
deleted file mode 100644
--- a/gone.txt
+++ /dev/null
@@ -1 +0,0 @@
-bye
diff --git a/logo.png b/logo.png
Binary files a/logo.png and b/logo.png differ
diff --git a/b.txt b/b.txt
--- a/b.txt
+++ b/b.txt
@@ -3,0 +4 @@
+beta
DIFF;

        $paths = array_map(fn (Patch $p): string => $p->path, PatchParser::parse($diff));

        expect($paths)->toBe(['a.txt', 'b.txt']);
    });

    it('attaches the commit hash from log output and separates commits', function (): void {
        $diff = <<<'DIFF'
commit 0123456789abcdef0123456789abcdef01234567
diff --git a/x b/x
--- a/x
+++ b/x
@@ -0,0 +1 @@
+one
commit fedcba9876543210fedcba9876543210fedcba98
diff --git a/x b/x
--- a/x
+++ b/x
@@ -1,0 +2 @@
+two
DIFF;

        $patches = PatchParser::parse($diff);

        expect($patches)->toHaveCount(2)
            ->and($patches[0]->commit)->toBe('0123456789abcdef0123456789abcdef01234567')
            ->and($patches[0]->addedLines)->toBe([1 => 'one'])
            ->and($patches[1]->commit)->toBe('fedcba9876543210fedcba9876543210fedcba98')
            ->and($patches[1]->addedLines)->toBe([2 => 'two']);
    });

    it('unquotes a path git had to quote and handles context lines', function (): void {
        $diff = <<<'DIFF'
diff --git "a/dir/sp ace.txt" "b/dir/sp ace.txt"
--- "a/dir/sp ace.txt"
+++ "b/dir/sp ace.txt"
@@ -1,2 +1,3 @@
 first
+inserted
 last
DIFF;

        $patches = PatchParser::parse($diff);

        expect($patches[0]->path)->toBe('dir/sp ace.txt')
            ->and($patches[0]->addedLines)->toBe([2 => 'inserted']);
    });

    it('drops a patch that adds nothing', function (): void {
        expect(PatchParser::parse("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +0,0 @@\n-gone\n"))->toBe([]);
    });

    it('joins the added lines for scanning', function (): void {
        $patch = PatchParser::parse("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -0,0 +5,2 @@\n+a\n+b\n")[0];

        expect($patch->text())->toBe("a\nb")
            ->and($patch->lineAt(1))->toBe(5)
            ->and($patch->lineAt(2))->toBe(6);
    });
});
