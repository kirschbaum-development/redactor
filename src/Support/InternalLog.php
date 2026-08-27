<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Support;

use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Logging for the redactor's own diagnostics.
 *
 * The redactor runs inside the logging pipeline, so a naive Log::warning() from
 * within a redaction re-enters the very handler that triggered it: redact ->
 * warn -> format -> redact -> warn, until the stack or the memory limit gives
 * out. This guard drops any diagnostic raised while one is already in flight,
 * and swallows failures from the logger itself.
 */
final class InternalLog
{
    private static bool $emitting = false;

    /**
     * @param  array<string, mixed>  $context
     */
    public static function warning(string $message, array $context = []): void
    {
        if (self::$emitting) {
            return;
        }

        self::$emitting = true;

        try {
            Log::warning($message, $context);
        } catch (Throwable) {
            // A broken logger must not turn into a broken application.
        } finally {
            self::$emitting = false;
        }
    }

    /**
     * Whether a diagnostic is currently being emitted. Exposed for tests.
     */
    public static function isEmitting(): bool
    {
        return self::$emitting;
    }
}
