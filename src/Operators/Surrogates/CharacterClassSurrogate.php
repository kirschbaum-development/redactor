<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators\Surrogates;

use Kirschbaum\Redactor\Support\DeterministicRandom;

/**
 * Replaces each character with a different one of the same class, leaving everything else alone.
 *
 *     sk_live_4eC39HqLyjWDarjt  ->  sk_live_9mB71TzKnQxPvfhs
 *     +1 (555) 867-5309         ->  +7 (204) 331-8874
 *
 * Length, separators, capitalisation and digit positions all survive, so
 * anything parsing the value keeps parsing it, and nothing of the original
 * survives except its shape. It works on any value, which is what makes it
 * the fallback for entities nobody wrote a generator for.
 */
class CharacterClassSurrogate implements SurrogateGenerator
{
    private const string LOWER = 'abcdefghijklmnopqrstuvwxyz';

    private const string UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

    private const string DIGITS = '0123456789';

    /**
     * Determine if the generator can stand in for the given value.
     */
    public function supports(string $entity, string $value): bool
    {
        return true;
    }

    /**
     * Generate a surrogate for the given value.
     *
     * @param  array<string, mixed>  $options
     */
    public function generate(string $value, DeterministicRandom $random, array $options = []): string
    {
        // A prefix such as "sk_live_" tells an on-call engineer which credential leaked, which is the point of the log line...
        $keep = $options['preserve_prefix'] ?? 0;
        $keep = is_int($keep) ? max(0, min($keep, strlen($value))) : 0;

        $out = substr($value, 0, $keep);

        $length = strlen($value);

        for ($i = $keep; $i < $length; $i++) {
            $char = $value[$i];

            $out .= match (true) {
                $char >= 'a' && $char <= 'z' => $random->pick(self::LOWER),
                $char >= 'A' && $char <= 'Z' => $random->pick(self::UPPER),
                $char >= '0' && $char <= '9' => $random->pick(self::DIGITS),
                // Separators, punctuation and anything multibyte pass through, since they carry the structure, not the secret...
                default => $char,
            };
        }

        return $out;
    }
}
