<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Logging;

use Kirschbaum\Redactor\Redactor;
use Monolog\LogRecord;
use Monolog\Processor\ProcessorInterface;

/**
 * The recommended way to redact Laravel logs.
 *
 * Redaction transforms a record's *content*, which is what a Monolog processor
 * is for. Owning the formatter instead - as ReadactFormatter does - means
 * dictating the output format, so enabling redaction silently replaces JSON or
 * line formatting with the package's own. A processor composes with whatever
 * formatter the application already uses.
 *
 * Register it on a channel with the RedactorTap:
 *
 *     'stack' => [
 *         'driver' => 'stack',
 *         'channels' => ['single'],
 *         'tap' => [\Kirschbaum\Redactor\Logging\RedactorTap::class],
 *     ],
 */
class RedactorProcessor implements ProcessorInterface
{
    public function __construct(
        protected Redactor $redactor,
        protected ?string $profile = null,
    ) {}

    public function __invoke(LogRecord $record): LogRecord
    {
        // redactSafely(), never redact(): this runs inside the logging
        // pipeline, where a thrown exception takes the channel down with it.
        $message = $this->redactor->redactSafely($record->message, $this->profile);

        $context = $this->redactArray($record->context);
        $extra = $this->redactArray($record->extra);

        return $record->with(
            message: is_string($message) ? $message : (string) json_encode($message),
            context: $context,
            extra: $extra,
        );
    }

    /**
     * @param  array<array-key, mixed>  $data
     * @return array<array-key, mixed>
     */
    protected function redactArray(array $data): array
    {
        if ($data === []) {
            return $data;
        }

        $redacted = $this->redactor->redactSafely($data, $this->profile);

        if (is_array($redacted)) {
            return $redacted;
        }

        // redactSafely() failed closed and returned a marker string. Keep the
        // record shaped as Monolog expects while still emitting nothing that
        // was not verified safe.
        return ['redaction' => $redacted];
    }
}
