<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Patterns;

/**
 * Structural checks that separate a real identifier from a number of the right
 * shape.
 *
 * A regex can only assert the shape. '/\b(?:\d[ -]*?){13,16}\b/' matches any
 * 13-to-16 digit run - order numbers, concatenated timestamps, tracking codes -
 * so used alone it reports far more cards than exist. Every serious detector
 * runs the checksum before reporting, and so does this one when a rule asks
 * for it.
 *
 * A validator answers one question: could this string actually be the thing
 * the pattern claims it is? Failing it means the match is left alone.
 */
final class Validator
{
    public const LUHN = 'luhn';

    public const IBAN = 'iban';

    public const SSN = 'ssn';

    /** @var array<int, string> */
    public const NAMES = [self::LUHN, self::IBAN, self::SSN];

    public static function passes(string $name, string $value): bool
    {
        return match ($name) {
            self::LUHN => self::luhn($value),
            self::IBAN => self::iban($value),
            self::SSN => self::ssn($value),
            // An unknown validator cannot be evaluated, so it must not veto a
            // match: failing open here would silently disable the rule.
            default => true,
        };
    }

    /**
     * The Luhn check digit used by payment cards, IMEIs and several national
     * identifiers.
     */
    public static function luhn(string $value): bool
    {
        $digits = preg_replace('/\D/', '', $value) ?? '';
        $length = strlen($digits);

        if ($length < 12 || $length > 19) {
            return false;
        }

        $sum = 0;
        $double = false;

        for ($i = $length - 1; $i >= 0; $i--) {
            $digit = (int) $digits[$i];

            if ($double) {
                $digit *= 2;

                if ($digit > 9) {
                    $digit -= 9;
                }
            }

            $sum += $digit;
            $double = ! $double;
        }

        return $sum % 10 === 0;
    }

    /**
     * ISO 13616 mod-97 check.
     */
    public static function iban(string $value): bool
    {
        $iban = strtoupper(preg_replace('/[^A-Za-z0-9]/', '', $value) ?? '');

        if (strlen($iban) < 15 || strlen($iban) > 34) {
            return false;
        }

        if (preg_match('/^[A-Z]{2}\d{2}[A-Z0-9]+$/', $iban) !== 1) {
            return false;
        }

        // Move the country code and check digits to the end, then map letters
        // to numbers (A=10 ... Z=35).
        $rearranged = substr($iban, 4).substr($iban, 0, 4);

        $numeric = '';
        foreach (str_split($rearranged) as $character) {
            $numeric .= ctype_alpha($character)
                ? (string) (ord($character) - 55)
                : $character;
        }

        // The value is far wider than an int, so take the modulus piecewise.
        $remainder = 0;
        foreach (str_split($numeric, 7) as $chunk) {
            $remainder = (int) (((string) $remainder).$chunk) % 97;
        }

        return $remainder === 1;
    }

    /**
     * US Social Security number allocation rules.
     *
     * Area 000, 666 and 900-999 have never been issued, and neither group 00
     * nor serial 0000 exists. Rejecting them removes most of the dates,
     * phone fragments and sequence numbers that match the SSN shape.
     */
    public static function ssn(string $value): bool
    {
        $digits = preg_replace('/\D/', '', $value) ?? '';

        if (strlen($digits) !== 9) {
            return false;
        }

        $area = (int) substr($digits, 0, 3);
        $group = (int) substr($digits, 3, 2);
        $serial = (int) substr($digits, 5, 4);

        if ($area === 0 || $area === 666 || $area >= 900) {
            return false;
        }

        return $group !== 0 && $serial !== 0;
    }
}
