<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Config;

use Kirschbaum\Redactor\RedactorConfig;

/**
 * The resolved profiles, kept alongside the raw config they were built from.
 *
 * Rebuilding a profile revalidates every pattern, recompiles the path trie and
 * re-parses every operator spec, measured at 0.23ms per call for 200 path
 * rules, several times the redaction it was preparing for. Invalidation
 * compares the raw array rather than hashing it, since PHP's array comparison
 * is a fast recursive check in C and any config change produces a different
 * array, so a stale security setting can never be served.
 */
class ProfileCache
{
    /** @var array<string, array{raw: array<mixed>, shared: array<mixed>, built: RedactorConfig}> */
    private static array $entries = [];

    private static int $builds = 0;

    /**
     * Get a build number no previously built profile has had.
     *
     * RedactorConfig is readonly and cannot hold the counter itself.
     */
    public static function nextBuildId(): int
    {
        return ++self::$builds;
    }

    /**
     * Get the cached profile if it was built from the same raw config.
     *
     * @param  array<mixed>  $raw  the profile's own config
     * @param  array<mixed>  $shared  package-level settings the profile was built with
     */
    public static function get(string $profile, array $raw, array $shared = []): ?RedactorConfig
    {
        $entry = self::$entries[$profile] ?? null;

        return $entry !== null && $entry['raw'] === $raw && $entry['shared'] === $shared
            ? $entry['built']
            : null;
    }

    /**
     * Cache the built profile against the raw config it was built from.
     *
     * @param  array<mixed>  $raw
     * @param  array<mixed>  $shared
     */
    public static function put(string $profile, array $raw, RedactorConfig $built, array $shared = []): RedactorConfig
    {
        self::$entries[$profile] = ['raw' => $raw, 'shared' => $shared, 'built' => $built];

        return $built;
    }
}
