<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static mixed redact(mixed $content, ?string $profile = null)
 * @method static \Kirschbaum\Redactor\RedactionResult redactWithMetadata(mixed $content, ?string $profile = null)
 * @method static mixed redactSafely(mixed $content, ?string $profile = null)
 * @method static bool registerSecret(string $value, string $entity = 'known_secret')
 * @method static void registerRecognizer(\Kirschbaum\Redactor\Recognition\Recognizer $recognizer)
 * @method static void registerOperator(string $name, \Kirschbaum\Redactor\Operators\Operator $operator)
 * @method static \Kirschbaum\Redactor\Operators\OperatorRegistry operators()
 * @method static array<string, string> validateProfiles()
 * @method static void registerCustomStrategy(string $name, \Kirschbaum\Redactor\Strategies\RedactionStrategyInterface $strategy)
 * @method static array<string> getAvailableProfiles()
 * @method static bool profileExists(string $profile)
 * @method static array<\Kirschbaum\Redactor\Strategies\RedactionStrategyInterface> getStrategies(?string $profile = null)
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
