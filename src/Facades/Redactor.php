<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static mixed redact(mixed $content, ?string $profile = null)
 * @method static void registerCustomStrategy(string $name, \Kirschbaum\Redactor\Strategies\RedactionStrategyInterface $strategy)
 * @method static array<string> getAvailableProfiles()
 * @method static bool profileExists(string $profile)
 * @method static array<\Kirschbaum\Redactor\Strategies\RedactionStrategyInterface> getStrategies(?string $profile = null)
 * @method static float calculateShannonEntropy(string $string)
 * @method static bool isCommonPattern(string $string, \Kirschbaum\Redactor\RedactorConfig $config)
 *
 * @see \Kirschbaum\Redactor\Redactor
 */
class Redactor extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \Kirschbaum\Redactor\Redactor::class;
    }
}
