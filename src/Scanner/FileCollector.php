<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Scanner;

use Symfony\Component\Finder\Finder;

class FileCollector
{
    /**
     * Collect all eligible files for scanning.
     *
     * @param  array<int, string>  $paths  Base paths to search (files or directories)
     * @param  array<int, string>  $excludePatterns  Glob-style patterns (e.g., ['*.min.js', 'node_modules/*'])
     * @param  int  $maxSizeBytes  Max file size to include (default 10MB)
     * @return array<int, string> Real paths of matched files
     */
    public static function collect(array $paths, array $excludePatterns = [], int $maxSizeBytes = 10_485_760): array
    {
        $files = [];
        $directoriesToScan = [];

        // Separate individual files from directories
        foreach ($paths as $path) {
            if (is_file($path)) {
                // Handle individual files
                if (self::isFileEligible($path, $maxSizeBytes)) {
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
            $finder = (new Finder)
                ->files()
                ->ignoreDotFiles(false)
                ->ignoreVCS(false)
                ->in($directory);

            foreach ($excludePatterns as $pattern) {
                $finder->notName($pattern);
            }

            foreach ($finder as $file) {
                if (self::isFileEligible($file->getPathname(), $maxSizeBytes)) {
                    $realPath = $file->getRealPath();
                    if ($realPath !== false) {
                        $files[] = $realPath;
                    }
                }
            }
        }

        return array_values(array_unique($files));
    }

    /**
     * Check if a file is eligible for scanning.
     */
    private static function isFileEligible(string $filePath, int $maxSizeBytes): bool
    {
        if (! is_readable($filePath)) {
            return false;
        }

        if (filesize($filePath) > $maxSizeBytes) {
            return false;
        }

        return true;
    }
}
