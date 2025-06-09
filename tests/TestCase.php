<?php

declare(strict_types=1);

namespace Tests;

use Closure;
use Illuminate\Support\Facades\Http;
use Kirschbaum\Redactor\RedactorServiceProvider;
use Mockery\MockInterface;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Orchestra\Testbench\TestCase as BaseTestCase;

class TestCase extends BaseTestCase
{
    use WithWorkbench;

    protected function getPackageProviders($app): array
    {
        return [
            RedactorServiceProvider::class,
        ];
    }

    protected function setUp(): void
    {
        parent::setUp();

        Http::preventingStrayRequests();
    }

    /**
     * Force bind a mock into the container for app() calls with parameters.
     */
    protected function mockBind(string $abstract, ?Closure $callback = null): MockInterface
    {
        $mock = $this->mock($abstract, $callback);

        app()->offsetSet($abstract, $mock);

        return $mock;
    }
}
