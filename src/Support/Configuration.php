<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Support;

use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;

/**
 * Configuration reads on the hot path.
 *
 * The config() helper resolves the repository through the container on
 * every call, which costs more than the lookup itself when a redaction reads
 * configuration several times. The repository is held per container instance
 * instead, so a fresh application in a test gets a fresh repository.
 */
final class Configuration
{
    private static ?Container $container = null;

    private static ?Repository $repository = null;

    /**
     * Get a configuration value.
     */
    public static function get(string $key, mixed $default = null): mixed
    {
        return self::repository()->get($key, $default);
    }

    /**
     * Get the configuration repository of the current container.
     */
    public static function repository(): Repository
    {
        $container = Container::getInstance();

        if (! self::$repository instanceof Repository || self::$container !== $container) {
            /** @var Repository $repository */
            $repository = $container->make('config');

            self::$container = $container;
            self::$repository = $repository;
        }

        return self::$repository;
    }
}
