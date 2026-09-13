<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor;

use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Routing\Router;
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
    /**
     * Register the package's services.
     */
    public function register(): void
    {
        // Merged during register() so a provider that reads redactor.* in its own register() sees it...
        $this->mergeConfigFrom(__DIR__.'/../config/redactor.php', 'redactor');

        $this->app->singleton(TokenStore::class, fn (): TokenStore => $this->createTokenStore());

        $this->app->singleton(Detokenizer::class, fn (): Detokenizer => new Detokenizer($this->app->make(TokenStore::class)));

        $this->app->singleton(Redactor::class, fn (): Redactor => $this->createRedactor());

        $this->app->singleton(Scanner::class, fn (): Scanner => $this->createScanner());
    }

    /**
     * Bootstrap the package's services.
     */
    public function boot(): void
    {
        $this->registerMiddleware();

        if ($this->app->runningInConsole()) {
            $this->registerCommands();
            $this->registerPublishing();
        }
    }

    /**
     * Create the redactor with the operators that need the container.
     */
    protected function createRedactor(): Redactor
    {
        $redactor = new Redactor;

        // The store is resolved on first use, since nothing needs the cache or encrypter until something is tokenised...
        $redactor->registerOperator('tokenize', new TokenizeOperator(
            new LazyTokenStore(fn (): TokenStore => $this->app->make(TokenStore::class))
        ));

        return $redactor;
    }

    /**
     * Create the token store from the configured cache store and TTL.
     */
    protected function createTokenStore(): TokenStore
    {
        $store = config('redactor.tokenization.store');
        $ttl = config('redactor.tokenization.ttl');

        return new CacheTokenStore(
            $this->app->make('cache')->store(is_string($store) && $store !== '' ? $store : null),
            $this->app->make(StringEncrypter::class),
            $ttl === null || $ttl === '' ? null : ConfigValue::positiveInt($ttl, 86_400, 'tokenization.ttl'),
        );
    }

    /**
     * Create the file scanner from the scan configuration.
     */
    protected function createScanner(): Scanner
    {
        return new Scanner(
            $this->app->make(Redactor::class),
            ConfigValue::positiveInt(config('redactor.scan.window_lines'), LineWindowReader::DEFAULT_WINDOW_LINES, 'scan.window_lines'),
            ConfigValue::positiveIntOrNull(config('redactor.scan.overlap_lines'), LineWindowReader::DEFAULT_OVERLAP_LINES, 'scan.overlap_lines') ?? 0,
            null,
            ConfigValue::bool(config('redactor.scan.decode'), true, 'scan.decode'),
        );
    }

    /**
     * Register the "redact" route middleware alias.
     */
    protected function registerMiddleware(): void
    {
        if (! $this->app->bound('router')) {
            return;
        }

        /** @var Router $router */
        $router = $this->app->make('router');

        $router->aliasMiddleware('redact', RedactResponse::class);
    }

    /**
     * Register the package's console commands.
     */
    protected function registerCommands(): void
    {
        $this->commands([
            RedactorScanCommand::class,
            RedactorValidateCommand::class,
        ]);
    }

    /**
     * Register the package's publishable resources.
     */
    protected function registerPublishing(): void
    {
        $this->publishes([
            __DIR__.'/../config/redactor.php' => config_path('redactor.php'),
        ], 'redactor-config');

        $this->publishes([
            __DIR__.'/../stubs/pre-commit' => base_path('.githooks/pre-commit'),
            __DIR__.'/../stubs/redactor-scan.yml' => base_path('.github/workflows/redactor-scan.yml'),
        ], 'redactor-ci');
    }
}
