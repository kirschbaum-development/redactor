<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators\Surrogates;

use Kirschbaum\Redactor\Support\DeterministicRandom;

/**
 * The general case: replace each character with a different one of the same
 * class, and leave everything else alone.
 *
 *     sk_live_4eC39HqLyjWDarjt  ->  sk_live_9mB71TzKnQxPvfhs
 *     +1 (555) 867-5309         ->  +7 (204) 331-8874
 *     2024-01-15T09:31:00Z      ->  7193-84-62T05:77:31Z
 *
 * Length, separators, capitalisation pattern and digit positions all survive,
 * so anything parsing the value keeps parsing it. Nothing of the original
 * survives except its shape.
 *
 * Works on any value, which is what makes it the fallback: a surrogate that
 * only handles the entities someone thought to write a generator for would
 * leave the long tail as "[REDACTED]".
 */
final class CharacterClassSurrogate implements SurrogateGenerator
{
    private const LOWER = 'abcdefghijklmnopqrstuvwxyz';

    private const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

    private const DIGITS = '0123456789';

    public function supports(string $entity, string $value): bool
    {
        return true;
    }

    /**
     * @param  array<string, mixed>  $options
     */
    public function generate(string $value, DeterministicRandom $random, array $options = []): string
    {
        // A prefix worth keeping: "sk_live_" tells an on-call engineer which
        // credential leaked, and knowing that is the point of the log line.
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
                // Separators, punctuation and anything multibyte pass through:
                // they carry the structure, not the secret.
                default => $char,
            };
        }

        return $out;
    }
}
