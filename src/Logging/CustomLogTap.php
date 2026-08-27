<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Logging;

use Illuminate\Log\Logger;
use Monolog\Handler\FormattableHandlerInterface;

/**
 * Replaces each handler's formatter with ReadactFormatter.
 *
 * Prefer RedactorTap, which adds redaction as a processor and leaves the
 * channel's output format alone. This tap necessarily discards whatever
 * formatter the handler was configured with, so a channel writing JSON stops
 * writing JSON the moment it is enabled.
 */
class CustomLogTap
{
    public function __invoke(Logger $logger): void
    {
        foreach ($logger->getHandlers() as $handler) {
            if ($handler instanceof FormattableHandlerInterface) {
                $handler->setFormatter(new ReadactFormatter);
            }
        }
    }
}
