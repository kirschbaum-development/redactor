<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor;

use Illuminate\Support\ServiceProvider;
use Kirschbaum\Redactor\Console\Commands\RedactorScanCommand;
use Kirschbaum\Redactor\Scanner\Scanner;

class RedactorServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // Must run in register(), not boot(): a provider that resolves Redactor
        // or reads redactor.* during its own register() would otherwise see no
        // configuration at all.
        $this->mergeConfigFrom(
            __DIR__.'/../config/redactor.php',
            'redactor'
        );

        $this->app->singleton(Redactor::class);
        $this->app->singleton(Scanner::class);

        $this->commands([
            RedactorScanCommand::class,
        ]);
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/redactor.php' => config_path('redactor.php'),
        ], 'redactor-config');
    }
}
