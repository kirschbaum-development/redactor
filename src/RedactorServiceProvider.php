<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor;

use Illuminate\Support\ServiceProvider;
use Kirschbaum\Redactor\Console\Commands\RedactorScanCommand;

class RedactorServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->bind(Redactor::class);

        $this->commands([
            RedactorScanCommand::class,
        ]);
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/redactor.php' => config_path('redactor.php'),
        ], 'redactor-config');

        $this->mergeConfigFrom(
            __DIR__.'/../config/redactor.php',
            'redactor'
        );
    }
}
