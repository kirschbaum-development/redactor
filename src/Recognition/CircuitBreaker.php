<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Recognition;

/**
 * Stops asking a recogniser that has stopped answering.
 *
 * A sidecar that is down fails every call at the full timeout, so inside a log
 * tap every line would wait seconds to be told nothing. After `threshold`
 * consecutive failures the breaker opens for `cooldown` seconds and the
 * strategy falls back to rules only; one success closes it again. State is per
 * process and deliberately not shared, because a breaker that needed the
 * cache to work would fail exactly when the cache does.
 */
class CircuitBreaker
{
    /** @var array<string, array{failures: int, open_until: int}> */
    private static array $state = [];

    /**
     * Determine if the recogniser behind the key may be called.
     */
    public static function allows(string $key): bool
    {
        $entry = self::$state[$key] ?? null;

        return $entry === null || $entry['open_until'] <= time();
    }

    /**
     * Record a success, closing the breaker.
     */
    public static function recordSuccess(string $key): void
    {
        unset(self::$state[$key]);
    }

    /**
     * Record a failure and determine if it opened the breaker.
     */
    public static function recordFailure(string $key, int $threshold, int $cooldownSeconds): bool
    {
        $entry = self::$state[$key] ?? ['failures' => 0, 'open_until' => 0];
        $entry['failures']++;

        if ($entry['failures'] >= max(1, $threshold)) {
            $entry['open_until'] = time() + max(1, $cooldownSeconds);
            $entry['failures'] = 0;
            self::$state[$key] = $entry;

            return true;
        }

        self::$state[$key] = $entry;

        return false;
    }

    /**
     * Determine if the breaker is open.
     */
    public static function isOpen(string $key): bool
    {
        return ! self::allows($key);
    }

    /**
     * Reset all breaker state.
     */
    public static function reset(): void
    {
        self::$state = [];
    }
}
