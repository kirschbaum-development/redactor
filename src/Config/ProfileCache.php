<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Config;

use Kirschbaum\Redactor\RedactorConfig;

/**
 * Resolved profiles, kept alongside the raw config they were built from.
 *
 * RedactorConfig::fromConfig() runs on every redaction, and rebuilding a profile
 * means revalidating every pattern, recompiling the path trie and re-parsing
 * every operator spec - work whose result cannot change unless the config does.
 * Left uncached it dominated: 0.23ms per call for a profile with 200 path rules,
 * several times the cost of the redaction it was preparing for.
 *
 * Invalidation compares the raw array rather than hashing it. PHP's array
 * identity check is a fast recursive comparison in C, where serialize() plus a
 * digest would cost more than the rebuild it was meant to avoid. Any config
 * change produces a different array and rebuilds, so the failure mode where a
 * cache quietly serves a stale security setting cannot occur.
 */
final class ProfileCache
{
    /** @var array<string, array{raw: array<mixed>, shared: array<mixed>, built: RedactorConfig}> */
    private static array $entries = [];

    private static int $builds = 0;

    /**
     * A number no previously built profile has had. RedactorConfig is a
     * readonly class and cannot hold the counter itself.
     */
    public static function nextBuildId(): int
    {
        return ++self::$builds;
    }

    /**
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
     * @param  array<mixed>  $raw
     * @param  array<mixed>  $shared
     */
    public static function put(string $profile, array $raw, RedactorConfig $built, array $shared = []): RedactorConfig
    {
        self::$entries[$profile] = ['raw' => $raw, 'shared' => $shared, 'built' => $built];

        return $built;
    }

    public static function flush(): void
    {
        self::$entries = [];
    }
}
