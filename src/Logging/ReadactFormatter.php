<?php

namespace Kirschbaum\Redactor\Logging;

use Kirschbaum\Redactor\Facades\Redactor;
use Monolog\Formatter\FormatterInterface;
use Monolog\LogRecord;

class ReadactFormatter implements FormatterInterface
{
    public function format(LogRecord $record): string
    {
        // Sanitize the message
        $message = Redactor::redact($record->message);

        // Format the main log line
        $output = sprintf(
            '[%s] %s.%s: %s',
            $record->datetime->format('Y-m-d H:i:s.u'),
            $record->channel,
            $record->level->getName(),
            is_string($message) ? $message : json_encode($message)
        );

        // Add sanitized context data if present
        if (! empty($record->context)) {
            $sanitizedContext = Redactor::redact($record->context);
            $output .= ' '.json_encode($sanitizedContext, JSON_UNESCAPED_SLASHES);
        }

        return $output."\n";
    }

    public function formatBatch(array $records): string
    {
        return $this->format($records[0]);
    }
}
