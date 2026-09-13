<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor;

use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\ServiceProvider;
use Kirschbaum\Redactor\Config\ConfigValue;
use Kirschbaum\Redactor\Console\Commands\RedactorScanCommand;
use Kirschbaum\Redactor\Console\Commands\RedactorValidateCommand;
use Kirschbaum\Redactor\Http\Middleware\RedactResponse;
use Kirschbaum\Redactor\Scanner\LineWindowReader;
use Kirschbaum\Redactor\Scanner\Scanner;
use Kirschbaum\Redactor\Tokenization\CacheTokenStore;
use Kirschbaum\Redactor\Tokenization\Detokenizer;
use Kirschbaum\Redactor\Tokenization\LazyTokenStore;
use Kirschbaum\Redactor\Tokenization\TokenizeOperator;
use Kirschbaum\Redactor\Tokenization\TokenStore;

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

        $this->app->singleton(TokenStore::class, function (): TokenStore {
            $store = Config::get('redactor.tokenization.store');
            $ttl = Config::get('redactor.tokenization.ttl');

            return new CacheTokenStore(
                $this->app->make('cache')->store(is_string($store) && $store !== '' ? $store : null),
                $this->app->make(StringEncrypter::class),
                $ttl === null || $ttl === '' ? null : ConfigValue::positiveInt($ttl, 86_400, 'tokenization.ttl'),
            );
        });

        $this->app->singleton(Detokenizer::class, fn (): Detokenizer => new Detokenizer($this->app->make(TokenStore::class)));

        $this->app->singleton(Redactor::class, function (): Redactor {
            $redactor = new Redactor;

            // The operator resolves the store on first use, not at boot: the
            // cache and encrypter are not needed until something is tokenised.
            $redactor->registerOperator('tokenize', new TokenizeOperator(new LazyTokenStore(fn () => $this->app->make(TokenStore::class))));

            return $redactor;
        });

        $this->app->singleton(Scanner::class, fn (): Scanner => new Scanner(
            $this->app->make(Redactor::class),
            ConfigValue::positiveInt(
                Config::get('redactor.scan.window_lines'),
                LineWindowReader::DEFAULT_WINDOW_LINES,
                'scan.window_lines'
            ),
            ConfigValue::positiveIntOrNull(
                Config::get('redactor.scan.overlap_lines'),
                LineWindowReader::DEFAULT_OVERLAP_LINES,
                'scan.overlap_lines'
            ) ?? 0,
            null,
            ConfigValue::bool(Config::get('redactor.scan.decode'), true, 'scan.decode'),
        ));

        $this->commands([
            RedactorScanCommand::class,
            RedactorValidateCommand::class,
        ]);
    }

    public function boot(): void
    {
        // Route::get(...)->middleware('redact:observability')
        if ($this->app->bound('router')) {
            /** @var Router $router */
            $router = $this->app->make('router');
            $router->aliasMiddleware('redact', RedactResponse::class);
        }

        $this->publishes([
            __DIR__.'/../config/redactor.php' => config_path('redactor.php'),
        ], 'redactor-config');

        // A pre-commit hook and a GitHub workflow that scan changes, for
        // projects that want the scanner as a gate rather than a command.
        $this->publishes([
            __DIR__.'/../stubs/pre-commit' => base_path('.githooks/pre-commit'),
            __DIR__.'/../stubs/redactor-scan.yml' => base_path('.github/workflows/redactor-scan.yml'),
        ], 'redactor-ci');
    }
}
