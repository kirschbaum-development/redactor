<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Facades;

use Illuminate\Support\Facades\Facade;
use Kirschbaum\Redactor\Testing\RedactorFake;

/**
 * @method static \Kirschbaum\Redactor\PendingRedaction profile(?string $profile)
 * @method static mixed redact(mixed $content, ?string $profile = null)
 * @method static \Kirschbaum\Redactor\RedactionResult inspect(mixed $content, ?string $profile = null, ?bool $mark = null)
 * @method static mixed redactSafely(mixed $content, ?string $profile = null)
 * @method static mixed detokenize(mixed $content)
 * @method static bool registerSecret(string $value, string $entity = 'known_secret')
 * @method static void registerOperator(string $name, \Kirschbaum\Redactor\Operators\Operator $operator)
 * @method static void registerRecognizer(\Kirschbaum\Redactor\Recognition\Recognizer $recognizer)
 * @method static void registerCustomStrategy(string $name, \Kirschbaum\Redactor\Strategies\Contracts\Strategy $strategy)
 * @method static \Kirschbaum\Redactor\Operators\OperatorRegistry operators()
 * @method static \Kirschbaum\Redactor\Recognition\RecognizerRegistry recognizers()
 * @method static array<string, string> validateProfiles()
 * @method static array<int, string> profiles()
 * @method static bool hasProfile(string $profile)
 * @method static array<int, \Kirschbaum\Redactor\Strategies\Contracts\Strategy> strategies(?string $profile = null)
 *
 * @see \Kirschbaum\Redactor\Redactor
 */
class Redactor extends Facade
{
    /**
     * Get the registered name of the component.
     */
    protected static function getFacadeAccessor(): string
    {
        return \Kirschbaum\Redactor\Redactor::class;
    }

    /**
     * Replace the bound redactor with a fake that records every call.
     *
     * It still redacts for real. Install it before the code under test
     * resolves the redactor, such as before a log channel is first used,
     * and assert afterwards with assertNeverEmitted() and friends.
     */
    public static function fake(): RedactorFake
    {
        $fake = new RedactorFake;

        static::swap($fake);

        return $fake;
    }
}
