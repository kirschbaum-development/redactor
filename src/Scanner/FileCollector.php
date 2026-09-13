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
    private const int BINARY_SNIFF_BYTES = 8192;

    /**
     * Collect the files eligible for scanning.
     *
     * @param  array<int, string>  $paths
     * @param  array<int, string>  $excludePatterns  globs matched against the basename and the path relative to each scanned directory
     * @return array<int, string>
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

        foreach ($paths as $path) {
            if (is_file($path)) {
                // An explicitly named file is scanned even if a pattern would exclude it...
                if (self::isFileEligible($path, $maxSizeBytes, $skipBinary)) {
                    $realPath = realpath($path);
                    if ($realPath !== false) {
                        $files[] = $realPath;
                    }
                }
            } elseif (is_dir($path)) {
                $directoriesToScan[] = $path;
            }
            // Non-existent paths are ignored here; the command warns about them...
        }

        foreach ($directoriesToScan as $directory) {
            // Resolve symlinks first: Symfony locates the git root by walking up the given
            // path, so a symlinked path makes ignoreVCSIgnored() silently do nothing...
            $directory = realpath($directory) ?: $directory;

            $finder = (new Finder)
                ->files()
                ->ignoreDotFiles(false)
                ->ignoreVCS(false)
                ->in($directory);

            if ($respectGitignore) {
                $finder->ignoreVCSIgnored(true);
            }

            // Prune whole directories during traversal, or 'vendor/*' walks every file under vendor first...
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
     * Determine if the file matches any exclude pattern.
     *
     * Patterns are tested against both the basename and the path relative to
     * the scanned directory: Symfony's notName() compares the basename only,
     * so 'vendor/*' would never match anything.
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
     * Determine if the repository-relative path matches any exclude pattern.
     *
     * The same test isExcluded() applies to walked files, for paths that
     * arrive from git rather than from the filesystem.
     *
     * @param  array<int, string>  $excludePatterns
     */
    public static function matchesExclude(string $relativePath, array $excludePatterns): bool
    {
        $relativePath = str_replace('\\', '/', $relativePath);
        $basename = basename($relativePath);

        foreach ($excludePatterns as $pattern) {
            if ($pattern !== '' && (fnmatch($pattern, $basename) || fnmatch($pattern, $relativePath))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get the directory prefixes that can be pruned during traversal.
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
     * Determine if the file is eligible for scanning.
     */
    private static function isFileEligible(string $filePath, int $maxSizeBytes, bool $skipBinary = true): bool
    {
        if (! is_readable($filePath)) {
            return false;
        }

        $size = @filesize($filePath);

        // filesize() returns false for a file that vanished since the walk; treat that as ineligible...
        if ($size === false || $size > $maxSizeBytes) {
            return false;
        }

        return ! $skipBinary || ! self::looksBinary($filePath);
    }

    /**
     * Determine if the file looks like binary content.
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

        // A NUL byte is the standard heuristic - git uses the same one...
        if (str_contains($sample, "\0")) {
            return true;
        }

        // Treat content that is neither valid UTF-8 nor predominantly printable as binary...
        if (mb_check_encoding($sample, 'UTF-8')) {
            return false;
        }

        $printable = strlen((string) preg_replace('/[^\P{C}\n\r\t]/u', '', $sample));

        return $printable < strlen($sample) * 0.7;
    }
}
