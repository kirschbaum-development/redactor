<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Scanner;

use SplFileInfo;
use Symfony\Component\Finder\Finder;

class FileCollector
{
    /**
     * How much of a file to inspect when deciding whether it is binary.
     */
    private const BINARY_SNIFF_BYTES = 8192;

    /**
     * Collect all eligible files for scanning.
     *
     * @param  array<int, string>  $paths  Base paths to search (files or directories)
     * @param  array<int, string>  $excludePatterns  Glob patterns matched against the
     *                                               basename and the path relative to
     *                                               each scanned directory, e.g.
     *                                               ['*.min.js', 'vendor/*']
     * @param  int  $maxSizeBytes  Max file size to include (default 10MB)
     * @param  bool  $skipBinary  Skip files that look binary
     * @param  bool  $respectGitignore  Skip files git is ignoring
     * @return array<int, string> Real paths of matched files
     */
    public static function collect(
        array $paths,
        array $excludePatterns = [],
        int $maxSizeBytes = 10_485_760,
        bool $skipBinary = true,
        bool $respectGitignore = true,
    ): array {
        $files = [];
        $directoriesToScan = [];

        // Separate individual files from directories
        foreach ($paths as $path) {
            if (is_file($path)) {
                // An explicitly named file is scanned even if a pattern would
                // exclude it: the caller asked for that file by name.
                if (self::isFileEligible($path, $maxSizeBytes, $skipBinary)) {
                    $realPath = realpath($path);
                    if ($realPath !== false) {
                        $files[] = $realPath;
                    }
                }
            } elseif (is_dir($path)) {
                $directoriesToScan[] = $path;
            }
            // Non-existent paths are silently ignored (command handles warnings)
        }

        // Process directories with Finder
        foreach ($directoriesToScan as $directory) {
            // Resolve symlinks first. Symfony locates the git root by walking
            // up the path it was given, so on macOS (/tmp -> /private/tmp) a
            // symlinked path makes ignoreVCSIgnored() silently do nothing.
            $directory = realpath($directory) ?: $directory;

            $finder = (new Finder)
                ->files()
                ->ignoreDotFiles(false)
                ->ignoreVCS(false)
                ->in($directory);

            if ($respectGitignore) {
                $finder->ignoreVCSIgnored(true);
            }

            // Prune whole directories during traversal where we can. Without
            // this a pattern like 'vendor/*' still walks every file under
            // vendor before rejecting it one at a time.
            foreach (self::directoryPrefixes($excludePatterns) as $prefix) {
                $finder->exclude($prefix);
            }

            foreach ($finder as $file) {
                if (self::isExcluded($file, $excludePatterns)) {
                    continue;
                }

                if (! self::isFileEligible($file->getPathname(), $maxSizeBytes, $skipBinary)) {
                    continue;
                }

                $realPath = $file->getRealPath();
                if ($realPath !== false) {
                    $files[] = $realPath;
                }
            }
        }

        return array_values(array_unique($files));
    }

    /**
     * Match a file against the exclude patterns.
     *
     * Symfony's notName() compares the *basename only*, so the shipped
     * defaults 'vendor/*' and 'node_modules/*' could never match anything and
     * every dependency was scanned. Patterns are tested against both the
     * basename and the path relative to the scanned directory, so 'vendor/*'
     * and '*.min.js' both behave as written.
     *
     * @param  array<int, string>  $excludePatterns
     */
    private static function isExcluded(SplFileInfo $file, array $excludePatterns): bool
    {
        if ($excludePatterns === []) {
            return false;
        }

        $basename = $file->getFilename();

        $relativePath = $file instanceof \Symfony\Component\Finder\SplFileInfo
            ? str_replace('\\', '/', $file->getRelativePathname())
            : $basename;

        foreach ($excludePatterns as $pattern) {
            if ($pattern === '') {
                continue;
            }

            if (fnmatch($pattern, $basename) || fnmatch($pattern, $relativePath)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Directory prefixes that can be pruned during traversal.
     *
     * 'vendor/*' and 'node_modules/**' both mean "skip that directory".
     *
     * @param  array<int, string>  $excludePatterns
     * @return array<int, string>
     */
    private static function directoryPrefixes(array $excludePatterns): array
    {
        $prefixes = [];

        foreach ($excludePatterns as $pattern) {
            if (! preg_match('#^([^*?\[\]]+)/\*{1,2}$#', $pattern, $matches)) {
                continue;
            }

            $prefixes[] = trim($matches[1], '/');
        }

        return array_values(array_unique(array_filter($prefixes)));
    }

    /**
     * Check if a file is eligible for scanning.
     */
    private static function isFileEligible(string $filePath, int $maxSizeBytes, bool $skipBinary = true): bool
    {
        if (! is_readable($filePath)) {
            return false;
        }

        $size = @filesize($filePath);

        // filesize() returns false for a file that vanished between the walk
        // and this check; treat that as ineligible rather than as size 0.
        if ($size === false || $size > $maxSizeBytes) {
            return false;
        }

        if ($skipBinary && self::looksBinary($filePath)) {
            return false;
        }

        return true;
    }

    /**
     * Whether a file looks like binary content.
     *
     * Scanning an image or a compiled artefact produces nothing but entropy
     * false positives, and reads the whole thing into memory to do it.
     */
    private static function looksBinary(string $filePath): bool
    {
        $handle = @fopen($filePath, 'rb');

        if ($handle === false) {
            return false;
        }

        $sample = fread($handle, self::BINARY_SNIFF_BYTES);
        fclose($handle);

        if ($sample === false || $sample === '') {
            return false;
        }

        // A NUL byte is the standard heuristic - git uses the same one.
        if (str_contains($sample, "\0")) {
            return true;
        }

        // Otherwise, treat content that is neither valid UTF-8 nor
        // predominantly printable as binary.
        if (mb_check_encoding($sample, 'UTF-8')) {
            return false;
        }

        $printable = strlen((string) preg_replace('/[^\P{C}\n\r\t]/u', '', $sample));

        return $printable < strlen($sample) * 0.7;
    }
}
