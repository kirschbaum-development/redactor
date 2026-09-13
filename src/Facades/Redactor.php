<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Facades;

use Illuminate\Support\Facades\Facade;
use Kirschbaum\Redactor\Testing\RedactorFake;

/**
 * @method static mixed redact(mixed $content, ?string $profile = null)
 * @method static \Kirschbaum\Redactor\RedactionResult redactWithMetadata(mixed $content, ?string $profile = null)
 * @method static mixed redactSafely(mixed $content, ?string $profile = null)
 * @method static mixed detokenize(mixed $content)
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

    /**
     * Replace the redactor with one that records every call, for tests.
     *
     * It still redacts for real. Install it before the code under test
     * resolves the redactor - before a log channel is first used, say - and
     * assert afterwards with assertNeverEmitted(), assertRedacted() and
     * friends.
     */
    public static function fake(): RedactorFake
    {
        $fake = new RedactorFake;

        static::swap($fake);

        return $fake;
    }
}
