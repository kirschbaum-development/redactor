<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Detection;

/**
 * The corroboration a match gets from what surrounds it.
 *
 * "token=" beside a high-entropy string is evidence, not proof, so it nudges
 * the score rather than deciding it. Shared by every detector so a keyword
 * means the same thing whichever one spotted the value.
 */
class KeywordContext
{
    /**
     * How much a nearby keyword is worth.
     */
    public const BOOST = 0.25;

    /**
     * How far back to look.
     *
     * Only the text ahead of the match is considered, since a keyword after
     * the match usually belongs to the next field.
     */
    public const WINDOW = 40;

    /** @var array<int, string> */
    public const KEYWORDS = [
        'secret', 'token', 'password', 'passwd', 'apikey', 'api_key', 'api-key',
        'credential', 'private', 'auth', 'bearer', 'key', 'card', 'cvv', 'ssn',
    ];

    /**
     * Add the context signal to a score when the surroundings corroborate it.
     */
    public static function boost(Confidence $confidence, string $subject, int $offset, string $key): Confidence
    {
        if (self::nearby($subject, $offset) || self::keyLooksSensitive($key)) {
            return $confidence->with('context', self::BOOST, 'a credential keyword appears alongside the match');
        }

        return $confidence;
    }

    /**
     * Determine if a credential keyword sits just before the match.
     */
    public static function nearby(string $subject, int $offset): bool
    {
        $start = max(0, $offset - self::WINDOW);
        $window = strtolower(substr($subject, $start, $offset - $start));

        if ($window === '') {
            return false;
        }

        foreach (self::KEYWORDS as $keyword) {
            if (str_contains($window, $keyword)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine if the key itself contains a credential keyword.
     */
    public static function keyLooksSensitive(string $key): bool
    {
        if ($key === '') {
            return false;
        }

        $lower = strtolower($key);

        foreach (self::KEYWORDS as $keyword) {
            if (str_contains($lower, $keyword)) {
                return true;
            }
        }

        return false;
    }
}
