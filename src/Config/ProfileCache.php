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
    /** @var array<string, array{raw: array<mixed>, built: RedactorConfig}> */
    private static array $entries = [];

    /**
     * @param  array<mixed>  $raw
     */
    public static function get(string $profile, array $raw): ?RedactorConfig
    {
        $entry = self::$entries[$profile] ?? null;

        return $entry !== null && $entry['raw'] === $raw ? $entry['built'] : null;
    }

    /**
     * @param  array<mixed>  $raw
     */
    public static function put(string $profile, array $raw, RedactorConfig $built): RedactorConfig
    {
        self::$entries[$profile] = ['raw' => $raw, 'built' => $built];

        return $built;
    }

    public static function flush(): void
    {
        self::$entries = [];
    }
}
