<?php

namespace Kirschbaum\Redactor\Logging;

use Illuminate\Log\Logger;
use Monolog\Handler\FormattableHandlerInterface;

class CustomLogTap
{
    /**
     * Customize the given logger instance.
     */
    public function __invoke(Logger $logger): void
    {
        foreach ($logger->getHandlers() as $handler) {
            if ($handler instanceof FormattableHandlerInterface) {
                $handler->setFormatter(new ReadactFormatter);
            }
        }
    }
}
