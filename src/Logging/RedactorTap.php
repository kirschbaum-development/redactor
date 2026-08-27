<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Logging;

use Illuminate\Log\Logger;
use Kirschbaum\Redactor\Redactor;
use Monolog\Logger as Monolog;

/**
 * Adds redaction to a channel without touching its output format.
 *
 *     'single' => [
 *         'driver' => 'single',
 *         'path' => storage_path('logs/laravel.log'),
 *         'tap' => [\Kirschbaum\Redactor\Logging\RedactorTap::class],
 *     ],
 *
 * Pass a profile name with the tap if the channel needs one other than the
 * configured default:
 *
 *     'tap' => [\Kirschbaum\Redactor\Logging\RedactorTap::class.':strict'],
 */
class RedactorTap
{
    public function __invoke(Logger $logger, ?string $profile = null): void
    {
        $monolog = $logger->getLogger();

        // Laravel types this as PSR-3; only Monolog takes processors.
        if (! $monolog instanceof Monolog) {
            return;
        }

        $monolog->pushProcessor(new RedactorProcessor(app(Redactor::class), $profile));
    }
}
