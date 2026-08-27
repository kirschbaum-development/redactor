<?php

declare(strict_types=1);

namespace Tests\Feature;

use Illuminate\Support\ServiceProvider;
use Kirschbaum\Redactor\Console\Commands\RedactorScanCommand;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\RedactorServiceProvider;

/**
 * Records what redactor config was visible at the moment its register()
 * method ran, which is the window mergeConfigFrom() has to beat.
 */
class ConfigProbeProvider extends ServiceProvider
{
    public static ?string $profileSeenDuringRegister = null;

    public static bool $redactorResolvableDuringRegister = false;

    public function register(): void
    {
        /** @var mixed $profile */
        $profile = $this->app['config']->get('redactor.default_profile');
        self::$profileSeenDuringRegister = is_string($profile) ? $profile : null;

        try {
            self::$redactorResolvableDuringRegister = $this->app->make(Redactor::class) instanceof Redactor;
        } catch (\Throwable) {
            self::$redactorResolvableDuringRegister = false;
        }
    }
}

describe('RedactorServiceProvider', function () {
    it('merges package config during register so other providers can read it', function () {
        ConfigProbeProvider::$profileSeenDuringRegister = null;

        $app = app();
        $app->register(RedactorServiceProvider::class, true);
        $app->register(ConfigProbeProvider::class, true);

        expect(ConfigProbeProvider::$profileSeenDuringRegister)->toBe('default');
    });

    it('binds the redactor early enough to resolve during another register()', function () {
        ConfigProbeProvider::$redactorResolvableDuringRegister = false;

        $app = app();
        $app->register(RedactorServiceProvider::class, true);
        $app->register(ConfigProbeProvider::class, true);

        expect(ConfigProbeProvider::$redactorResolvableDuringRegister)->toBeTrue();
    });

    it('publishes the config file under the redactor-config tag', function () {
        $paths = ServiceProvider::pathsToPublish(RedactorServiceProvider::class, 'redactor-config');

        expect($paths)->not->toBeEmpty()
            ->and(array_values($paths)[0])->toEndWith('redactor.php');
    });

    it('registers the scan command', function () {
        expect(array_keys(app('Illuminate\Contracts\Console\Kernel')->all()))->toContain('redactor:scan')
            ->and(app(RedactorScanCommand::class))->toBeInstanceOf(RedactorScanCommand::class);
    });
});
