<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Support;

/**
 * preg_* wrappers that cannot silently report "no secret here".
 *
 * preg_match() returns false on a PCRE failure, such as a backtrack limit or
 * bad UTF-8, which is indistinguishable from a clean "no match" if the caller
 * treats the result as a boolean, so an errored pattern would let the value
 * through unredacted. Every call here forces the caller to state what an
 * error means for that pattern, so the safe answer is chosen deliberately
 * rather than inherited from a falsy return value.
 */
class Pcre
{
    /**
     * Determine if the pattern matches the subject, reporting an engine failure as $onError.
     *
     * @param  bool  $onError  what an engine failure should be reported as
     * @param  string|null  $rule  pattern name, used only for the diagnostic
     */
    public static function matches(string $pattern, string $subject, bool $onError, ?string $rule = null): bool
    {
        $result = @preg_match($pattern, $subject);

        if ($result === false) {
            self::reportFailure($pattern, $rule, strlen($subject));

            return $onError;
        }

        return $result === 1;
    }

    /**
     * Replace every match using a callback, or return null when the engine fails.
     *
     * A null lets callers fail closed rather than emit a half-substituted string.
     *
     * @param  callable(array<int|string, string>): string  $callback
     */
    public static function replaceCallback(
        string $pattern,
        callable $callback,
        string $subject,
        ?string $rule = null,
        int $flags = 0
    ): ?string {
        $result = @preg_replace_callback($pattern, $callback, $subject, -1, $count, $flags);

        if ($result === null || preg_last_error() !== PREG_NO_ERROR) {
            self::reportFailure($pattern, $rule, strlen($subject));

            return null;
        }

        return $result;
    }

    /**
     * Determine if a pattern compiles at all.
     */
    public static function isValidPattern(string $pattern): bool
    {
        return @preg_match($pattern, '') !== false;
    }

    /**
     * Log an engine failure.
     */
    private static function reportFailure(string $pattern, ?string $rule, int $subjectLength): void
    {
        InternalLog::warning('Redaction pattern failed to evaluate; failing closed', [
            'rule' => $rule,
            'pattern' => $pattern,
            'subject_length' => $subjectLength,
            'preg_error' => preg_last_error_msg(),
        ]);
    }
}
