<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Logging;

use Kirschbaum\Redactor\Facades\Redactor;
use Monolog\Formatter\FormatterInterface;
use Monolog\LogRecord;

/**
 * Redacts a record and renders it.
 *
 * Prefer RedactorProcessor: redaction changes a record's content, not its
 * presentation, and a formatter can only be installed by replacing whatever
 * the channel already had. This class is kept for channels that want a
 * self-contained drop-in.
 *
 * Pass an inner formatter to keep the channel's own output format:
 *
 *     new ReadactFormatter(new JsonFormatter)
 */
class ReadactFormatter implements FormatterInterface
{
    public function __construct(
        protected ?FormatterInterface $inner = null,
    ) {}

    public function format(LogRecord $record): string
    {
        $record = $this->redact($record);

        if ($this->inner !== null) {
            // Monolog 3 types FormatterInterface::format() as mixed, since a
            // formatter may render to something other than a string.
            $formatted = $this->inner->format($record);

            return is_string($formatted) ? $formatted : (string) json_encode($formatted);
        }

        $output = sprintf(
            '[%s] %s.%s: %s',
            $record->datetime->format('Y-m-d H:i:s.u'),
            $record->channel,
            $record->level->getName(),
            $record->message
        );

        if ($record->context !== []) {
            $output .= ' '.json_encode($record->context, JSON_UNESCAPED_SLASHES);
        }

        if ($record->extra !== []) {
            $output .= ' '.json_encode($record->extra, JSON_UNESCAPED_SLASHES);
        }

        return $output."\n";
    }

    /**
     * @param  array<int, LogRecord>  $records
     */
    public function formatBatch(array $records): string
    {
        if ($this->inner !== null) {
            $formatted = $this->inner->formatBatch(array_map(
                fn (LogRecord $record) => $this->redact($record),
                $records
            ));

            return is_string($formatted) ? $formatted : (string) json_encode($formatted);
        }

        // Previously this returned format($records[0]) - every record but the
        // first was silently dropped by any batching handler.
        $output = '';

        foreach ($records as $record) {
            $output .= $this->format($record);
        }

        return $output;
    }

    /**
     * Redact a record in place, using the same never-throw path as the
     * processor.
     */
    protected function redact(LogRecord $record): LogRecord
    {
        $message = Redactor::redactSafely($record->message);
        $context = $record->context === [] ? [] : Redactor::redactSafely($record->context);
        $extra = $record->extra === [] ? [] : Redactor::redactSafely($record->extra);

        return $record->with(
            message: is_string($message) ? $message : (string) json_encode($message),
            context: is_array($context) ? $context : ['redaction' => $context],
            extra: is_array($extra) ? $extra : ['redaction' => $extra],
        );
    }
}
