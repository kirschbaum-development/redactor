<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Config;

use InvalidArgumentException;

/**
 * Coercion helpers for profile configuration.
 *
 * Every value in config/redactor.php can arrive as a string, because Laravel's
 * env() only casts "true", "false", "null" and "empty" - numbers stay strings.
 * Validating with is_int()/is_float() therefore rejects exactly the values the
 * documented environment variables produce, so each documented knob silently
 * fell back to its default. These helpers accept the string forms and reject
 * genuinely malformed input loudly.
 */
final class ConfigValue
{
    public static function bool(mixed $value, bool $default, string $path): bool
    {
        if ($value === null) {
            return $default;
        }

        if (is_bool($value)) {
            return $value;
        }

        if (is_int($value) && ($value === 0 || $value === 1)) {
            return $value === 1;
        }

        if (is_string($value)) {
            $normalised = strtolower(trim($value));

            if (in_array($normalised, ['true', '1', 'yes', 'on'], true)) {
                return true;
            }

            if (in_array($normalised, ['false', '0', 'no', 'off', ''], true)) {
                return false;
            }
        }

        throw new InvalidArgumentException(sprintf(
            'Redactor config [%s] must be a boolean, got %s.',
            $path,
            self::describe($value)
        ));
    }

    public static function string(mixed $value, string $default, string $path): string
    {
        if ($value === null) {
            return $default;
        }

        if (is_string($value)) {
            return $value;
        }

        if (is_int($value) || is_float($value)) {
            return (string) $value;
        }

        throw new InvalidArgumentException(sprintf(
            'Redactor config [%s] must be a string, got %s.',
            $path,
            self::describe($value)
        ));
    }

    /**
     * A positive integer, or null when the feature is switched off.
     */
    public static function positiveIntOrNull(mixed $value, ?int $default, string $path): ?int
    {
        if ($value === null) {
            return $default;
        }

        if (is_string($value) && trim($value) === '') {
            return null;
        }

        $int = self::toInt($value, $path);

        if ($int <= 0) {
            throw new InvalidArgumentException(sprintf(
                'Redactor config [%s] must be a positive integer or null, got %d.',
                $path,
                $int
            ));
        }

        return $int;
    }

    public static function positiveInt(mixed $value, int $default, string $path): int
    {
        return self::positiveIntOrNull($value, $default, $path) ?? $default;
    }

    public static function float(mixed $value, float $default, string $path): float
    {
        if ($value === null) {
            return $default;
        }

        if (is_float($value) || is_int($value)) {
            return (float) $value;
        }

        if (is_string($value) && is_numeric(trim($value))) {
            return (float) trim($value);
        }

        throw new InvalidArgumentException(sprintf(
            'Redactor config [%s] must be a number, got %s.',
            $path,
            self::describe($value)
        ));
    }

    /**
     * @param  array<int, string>  $allowed
     */
    public static function enum(mixed $value, array $allowed, string $default, string $path): string
    {
        $string = self::string($value, $default, $path);

        if (! in_array($string, $allowed, true)) {
            throw new InvalidArgumentException(sprintf(
                'Redactor config [%s] must be one of [%s], got "%s".',
                $path,
                implode(', ', $allowed),
                $string
            ));
        }

        return $string;
    }

    /**
     * @return array<int, string>
     */
    public static function stringList(mixed $value, string $path): array
    {
        if ($value === null) {
            return [];
        }

        if (! is_array($value)) {
            throw new InvalidArgumentException(sprintf(
                'Redactor config [%s] must be an array, got %s.',
                $path,
                self::describe($value)
            ));
        }

        $out = [];

        foreach ($value as $item) {
            if (is_string($item)) {
                $out[] = $item;
            }
        }

        return $out;
    }

    /**
     * @return array<string, mixed>
     */
    public static function map(mixed $value, string $path): array
    {
        if ($value === null) {
            return [];
        }

        if (! is_array($value)) {
            throw new InvalidArgumentException(sprintf(
                'Redactor config [%s] must be an array, got %s.',
                $path,
                self::describe($value)
            ));
        }

        /** @var array<string, mixed> $normalised */
        $normalised = [];

        foreach ($value as $key => $item) {
            $normalised[(string) $key] = $item;
        }

        return $normalised;
    }

    private static function toInt(mixed $value, string $path): int
    {
        if (is_int($value)) {
            return $value;
        }

        if (is_float($value) && floor($value) === $value) {
            return (int) $value;
        }

        if (is_string($value)) {
            $trimmed = trim($value);

            // Reject "12abc" and "1.5", which (int) would silently accept.
            if (preg_match('/^-?\d+$/', $trimmed) === 1) {
                return (int) $trimmed;
            }
        }

        throw new InvalidArgumentException(sprintf(
            'Redactor config [%s] must be an integer, got %s.',
            $path,
            self::describe($value)
        ));
    }

    private static function describe(mixed $value): string
    {
        if (is_object($value)) {
            return get_class($value);
        }

        if (is_string($value)) {
            return sprintf('string("%s")', $value);
        }

        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }

        if (is_scalar($value)) {
            return sprintf('%s(%s)', gettype($value), (string) $value);
        }

        return gettype($value);
    }
}
