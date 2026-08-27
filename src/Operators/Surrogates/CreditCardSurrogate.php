<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators\Surrogates;

use Kirschbaum\Redactor\Support\DeterministicRandom;

/**
 * A stable fake card number that still passes Luhn.
 *
 *     4111 1111 1111 1111  ->  4111 1193 7420 8846
 *
 * Length, grouping and the issuer prefix survive; the account number does not.
 * The check digit is recomputed so the result validates, which matters more
 * than it sounds: a fixture, a replayed request or a test double carrying an
 * invalid card fails at a different layer than the one under test, and the
 * resulting bug hunt is expensive.
 *
 * The BIN is kept by default. It identifies the issuer and card type - the
 * thing fraud and finance teams actually aggregate on - and is not specific to
 * a cardholder.
 */
final class CreditCardSurrogate implements SurrogateGenerator
{
    private const DEFAULT_BIN_LENGTH = 6;

    public function supports(string $entity, string $value): bool
    {
        if ($entity === 'credit_card') {
            return true;
        }

        $digits = preg_replace('/\D/', '', $value) ?? '';

        return strlen($digits) >= 12 && strlen($digits) <= 19;
    }

    /**
     * @param  array<string, mixed>  $options
     */
    public function generate(string $value, DeterministicRandom $random, array $options = []): string
    {
        $digits = preg_replace('/\D/', '', $value) ?? '';
        $count = strlen($digits);

        if ($count < 2) {
            return $value;
        }

        $binLength = $options['preserve_bin'] ?? self::DEFAULT_BIN_LENGTH;
        $binLength = is_int($binLength) ? max(0, min($binLength, $count - 2)) : self::DEFAULT_BIN_LENGTH;
        $binLength = min($binLength, $count - 2);

        $generated = substr($digits, 0, $binLength);

        // Everything between the BIN and the check digit is replaced.
        for ($i = $binLength; $i < $count - 1; $i++) {
            $generated .= $random->digit();
        }

        $generated .= self::checkDigit($generated);

        return self::reapplyFormatting($value, $generated);
    }

    /**
     * The digit that makes a Luhn sum land on a multiple of ten.
     */
    private static function checkDigit(string $withoutCheck): string
    {
        $sum = 0;
        $double = true; // The check digit sits in an undoubled position.

        for ($i = strlen($withoutCheck) - 1; $i >= 0; $i--) {
            $digit = (int) $withoutCheck[$i];

            if ($double) {
                $digit *= 2;
                if ($digit > 9) {
                    $digit -= 9;
                }
            }

            $sum += $digit;
            $double = ! $double;
        }

        return (string) ((10 - ($sum % 10)) % 10);
    }

    /**
     * Put the original spaces and dashes back where they were.
     */
    private static function reapplyFormatting(string $original, string $digits): string
    {
        $out = '';
        $index = 0;
        $length = strlen($original);

        for ($i = 0; $i < $length; $i++) {
            $char = $original[$i];

            if ($char >= '0' && $char <= '9') {
                $out .= $digits[$index] ?? $char;
                $index++;

                continue;
            }

            $out .= $char;
        }

        return $out;
    }
}
