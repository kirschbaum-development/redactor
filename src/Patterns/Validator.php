<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Patterns;

/**
 * Structural checks that separate a real identifier from a number of the right shape.
 *
 * A regex can only assert shape: '/\b(?:\d[ -]*?){13,16}\b/' matches any 13 to
 * 16 digit run, so used alone it reports far more cards than exist. Every
 * serious detector runs the checksum before reporting, and so does this one
 * when a rule asks for it. Failing a validator means the match is left alone.
 */
class Validator
{
    public const LUHN = 'luhn';

    public const IBAN = 'iban';

    public const SSN = 'ssn';

    public const NHS = 'nhs';

    public const BSN = 'bsn';

    public const STEUER_ID = 'steuer_id';

    public const NIR = 'nir';

    public const DNI = 'dni';

    public const CODICE_FISCALE = 'codice_fiscale';

    public const BELGIAN_NATIONAL_NUMBER = 'belgian_national_number';

    public const PERSONNUMMER = 'personnummer';

    public const FODSELSNUMMER = 'fodselsnummer';

    public const SIN = 'sin';

    public const TFN = 'tfn';

    public const VAT = 'vat';

    /** @var array<int, string> */
    public const NAMES = [
        self::LUHN, self::IBAN, self::SSN, self::NHS, self::BSN, self::STEUER_ID, self::NIR, self::DNI,
        self::CODICE_FISCALE, self::BELGIAN_NATIONAL_NUMBER, self::PERSONNUMMER, self::FODSELSNUMMER,
        self::SIN, self::TFN, self::VAT,
    ];

    /** @var array<string, callable(string): bool> */
    protected static array $custom = [];

    /**
     * Register a validator of your own, usable from config by name.
     *
     * @param  callable(string): bool  $check
     */
    public static function extend(string $name, callable $check): void
    {
        static::$custom[$name] = $check;
    }

    /**
     * Determine if a validator of this name exists.
     */
    public static function exists(string $name): bool
    {
        return isset(static::$custom[$name]) || in_array($name, self::NAMES, true);
    }

    /**
     * Determine if a value passes the named validator.
     */
    public static function passes(string $name, string $value): bool
    {
        if (isset(static::$custom[$name])) {
            return (bool) (static::$custom[$name])($value);
        }

        return match ($name) {
            self::LUHN => self::luhn($value),
            self::IBAN => self::iban($value),
            self::SSN => self::ssn($value),
            self::NHS => self::nhs($value),
            self::BSN => self::bsn($value),
            self::STEUER_ID => self::steuerId($value),
            self::NIR => self::nir($value),
            self::DNI => self::dni($value),
            self::CODICE_FISCALE => self::codiceFiscale($value),
            self::BELGIAN_NATIONAL_NUMBER => self::belgianNationalNumber($value),
            self::PERSONNUMMER => self::personnummer($value),
            self::FODSELSNUMMER => self::fodselsnummer($value),
            self::SIN => self::sin($value),
            self::TFN => self::tfn($value),
            self::VAT => self::vat($value),
            // An unknown validator cannot be evaluated, so it must not veto a match and silently disable the rule...
            default => true,
        };
    }

    /**
     * Determine if a value passes the Luhn check used by payment cards and IMEIs.
     */
    public static function luhn(string $value): bool
    {
        $digits = self::digits($value);
        $length = strlen($digits);

        if ($length < 12 || $length > 19) {
            return false;
        }

        return self::luhnSum($digits) % 10 === 0;
    }

    /**
     * Determine if a value passes the ISO 13616 mod-97 check.
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

        return self::mod97(substr($iban, 4).substr($iban, 0, 4)) === 1;
    }

    /**
     * Determine if a value follows the US Social Security number allocation rules.
     *
     * Area 000, 666 and 900-999 have never been issued, and neither group 00
     * nor serial 0000 exists. Rejecting them removes most of the dates, phone
     * fragments and sequence numbers that match the SSN shape.
     */
    public static function ssn(string $value): bool
    {
        $digits = self::digits($value);

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

    /**
     * Determine if a value is a valid NHS number (ten digits, mod-11 check digit).
     */
    public static function nhs(string $value): bool
    {
        $digits = self::digits($value);

        if (strlen($digits) !== 10) {
            return false;
        }

        $sum = 0;

        for ($i = 0; $i < 9; $i++) {
            $sum += (int) $digits[$i] * (10 - $i);
        }

        $check = 11 - ($sum % 11);

        if ($check === 11) {
            $check = 0;
        }

        return $check !== 10 && $check === (int) $digits[9];
    }

    /**
     * Determine if a value is a valid Dutch citizen service number (the eleven-proof).
     */
    public static function bsn(string $value): bool
    {
        $digits = self::digits($value);

        if (strlen($digits) !== 9) {
            return false;
        }

        $sum = 0;

        for ($i = 0; $i < 8; $i++) {
            $sum += (int) $digits[$i] * (9 - $i);
        }

        $sum -= (int) $digits[8];

        return $sum % 11 === 0;
    }

    /**
     * Determine if a value is a valid German tax identification number.
     *
     * Eleven digits, not starting with zero, exactly one digit repeated among
     * the first ten, and a check digit computed by the ISO 7064 mod 11,10 scheme.
     */
    public static function steuerId(string $value): bool
    {
        $digits = self::digits($value);

        if (preg_match('/^[1-9]\d{10}$/', $digits) !== 1) {
            return false;
        }

        $counts = array_count_values(str_split(substr($digits, 0, 10)));
        $repeated = array_filter($counts, fn (int $n): bool => $n > 1);

        if (count($repeated) !== 1 || max($repeated) > 3) {
            return false;
        }

        $product = 10;

        for ($i = 0; $i < 10; $i++) {
            $sum = ((int) $digits[$i] + $product) % 10;

            if ($sum === 0) {
                $sum = 10;
            }

            $product = ($sum * 2) % 11;
        }

        $check = 11 - $product;

        if ($check === 10) {
            $check = 0;
        }

        return $check === (int) $digits[10];
    }

    /**
     * Determine if a value is a valid French social security number (NIR with its key).
     */
    public static function nir(string $value): bool
    {
        $value = strtoupper(preg_replace('/\s/', '', $value) ?? '');

        if (preg_match('/^[12]\d{2}(0[1-9]|1[0-2]|[2-9]\d)(\d{2}|2A|2B)\d{6}\d{2}$/', $value) !== 1) {
            return false;
        }

        $number = str_replace(['2A', '2B'], ['19', '18'], substr($value, 0, 13));
        $key = (int) substr($value, 13, 2);

        return 97 - self::mod97($number) === $key;
    }

    /**
     * Determine if a value is a valid Spanish DNI or NIE (the letter is a mod-23 check).
     */
    public static function dni(string $value): bool
    {
        $value = strtoupper(preg_replace('/[\s-]/', '', $value) ?? '');
        $letters = 'TRWAGMYFPDXBNJZSQVHLCKE';

        if (preg_match('/^(\d{8})([A-Z])$/', $value, $m) === 1) {
            return $letters[(int) $m[1] % 23] === $m[2];
        }

        if (preg_match('/^([XYZ])(\d{7})([A-Z])$/', $value, $m) === 1) {
            $number = (int) (['X' => '0', 'Y' => '1', 'Z' => '2'][$m[1]].$m[2]);

            return $letters[$number % 23] === $m[3];
        }

        return false;
    }

    /**
     * Determine if a value is a valid Italian fiscal code (the last letter is a check).
     */
    public static function codiceFiscale(string $value): bool
    {
        $value = strtoupper(preg_replace('/\s/', '', $value) ?? '');

        if (preg_match('/^[A-Z]{6}\d{2}[A-EHLMPRST]\d{2}[A-Z]\d{3}[A-Z]$/', $value) !== 1) {
            return false;
        }

        $odd = [
            '0' => 1, '1' => 0, '2' => 5, '3' => 7, '4' => 9, '5' => 13, '6' => 15, '7' => 17, '8' => 19, '9' => 21,
            'A' => 1, 'B' => 0, 'C' => 5, 'D' => 7, 'E' => 9, 'F' => 13, 'G' => 15, 'H' => 17, 'I' => 19, 'J' => 21,
            'K' => 2, 'L' => 4, 'M' => 18, 'N' => 20, 'O' => 11, 'P' => 3, 'Q' => 6, 'R' => 8, 'S' => 12, 'T' => 14,
            'U' => 16, 'V' => 10, 'W' => 22, 'X' => 25, 'Y' => 24, 'Z' => 23,
        ];

        $sum = 0;

        for ($i = 0; $i < 15; $i++) {
            $char = $value[$i];

            $sum += $i % 2 === 0
                ? $odd[$char]
                : (ctype_digit($char) ? (int) $char : ord($char) - 65);
        }

        return chr(65 + $sum % 26) === $value[15];
    }

    /**
     * Determine if a value is a valid Belgian national register number (mod-97 check).
     */
    public static function belgianNationalNumber(string $value): bool
    {
        $digits = self::digits($value);

        if (strlen($digits) !== 11) {
            return false;
        }

        $base = substr($digits, 0, 9);
        $check = (int) substr($digits, 9, 2);

        // Births from 2000 on are checked with a leading 2...
        return 97 - ((int) $base % 97) === $check
            || 97 - ((int) ('2'.$base) % 97) === $check;
    }

    /**
     * Determine if a value is a valid Swedish personal identity number (a date and a Luhn check).
     */
    public static function personnummer(string $value): bool
    {
        $digits = self::digits($value);

        if (strlen($digits) === 12) {
            $digits = substr($digits, 2);
        }

        if (strlen($digits) !== 10 || ! self::plausibleDate((int) substr($digits, 2, 2), (int) substr($digits, 4, 2))) {
            return false;
        }

        return self::luhnSum($digits) % 10 === 0;
    }

    /**
     * Determine if a value is a valid Norwegian national identity number (two mod-11 checks).
     */
    public static function fodselsnummer(string $value): bool
    {
        $digits = self::digits($value);

        if (strlen($digits) !== 11) {
            return false;
        }

        $first = self::mod11Check($digits, [3, 7, 6, 1, 8, 9, 4, 5, 2]);
        $second = self::mod11Check($digits, [5, 4, 3, 2, 7, 6, 5, 4, 3, 2]);

        return $first === (int) $digits[9] && $second === (int) $digits[10];
    }

    /**
     * Determine if a value is a valid Canadian social insurance number (nine digits, Luhn).
     */
    public static function sin(string $value): bool
    {
        $digits = self::digits($value);

        return strlen($digits) === 9 && $digits[0] !== '0' && self::luhnSum($digits) % 10 === 0;
    }

    /**
     * Determine if a value is a valid Australian tax file number (weighted mod-11).
     */
    public static function tfn(string $value): bool
    {
        $digits = self::digits($value);

        $weights = match (strlen($digits)) {
            9 => [1, 4, 3, 7, 5, 8, 6, 9, 10],
            8 => [10, 7, 8, 4, 6, 3, 5, 1],
            default => null,
        };

        if ($weights === null) {
            return false;
        }

        $sum = 0;

        foreach (str_split($digits) as $i => $digit) {
            $sum += (int) $digit * $weights[$i];
        }

        return $sum % 11 === 0;
    }

    /**
     * Determine if a value is a plausible EU VAT number.
     *
     * The country prefix selects the check. Countries with a published
     * checksum are verified; the rest are accepted on format alone.
     */
    public static function vat(string $value): bool
    {
        $value = strtoupper(preg_replace('/[\s.-]/', '', $value) ?? '');

        if (preg_match('/^([A-Z]{2})([A-Z0-9]{2,13})$/', $value, $m) !== 1) {
            return false;
        }

        [, $country, $body] = $m;

        return match ($country) {
            'DE' => preg_match('/^[1-9]\d{8}$/', $body) === 1 && self::vatGermany($body),
            'NL' => preg_match('/^\d{9}B\d{2}$/', $body) === 1 && self::vatNetherlands($body),
            'GB', 'XI' => preg_match('/^\d{9}(\d{3})?$/', $body) === 1 && self::vatBritain($body),
            'IT' => preg_match('/^\d{11}$/', $body) === 1 && self::luhnSum($body) % 10 === 0,
            'FR' => preg_match('/^[A-Z0-9]{2}\d{9}$/', $body) === 1 && self::vatFrance($body),
            'BE' => preg_match('/^[01]\d{9}$/', $body) === 1 && 97 - ((int) substr($body, 0, 8) % 97) === (int) substr($body, 8, 2),
            'ES' => preg_match('/^[A-Z0-9]\d{7}[A-Z0-9]$/', $body) === 1,
            'SE' => preg_match('/^\d{10}01$/', $body) === 1 && self::luhnSum(substr($body, 0, 10)) % 10 === 0,
            'AT' => preg_match('/^U\d{8}$/', $body) === 1,
            'DK' => preg_match('/^\d{8}$/', $body) === 1,
            'FI' => preg_match('/^\d{8}$/', $body) === 1,
            'IE' => preg_match('/^\d[A-Z0-9+*]\d{5}[A-Z]{1,2}$/', $body) === 1,
            'PL' => preg_match('/^\d{10}$/', $body) === 1,
            'PT' => preg_match('/^\d{9}$/', $body) === 1,
            'LU' => preg_match('/^\d{8}$/', $body) === 1,
            'CZ' => preg_match('/^\d{8,10}$/', $body) === 1,
            'HU' => preg_match('/^\d{8}$/', $body) === 1,
            'RO' => preg_match('/^\d{2,10}$/', $body) === 1,
            'SK' => preg_match('/^\d{10}$/', $body) === 1,
            'SI' => preg_match('/^\d{8}$/', $body) === 1,
            'HR' => preg_match('/^\d{11}$/', $body) === 1,
            'BG' => preg_match('/^\d{9,10}$/', $body) === 1,
            'EE', 'LT' => preg_match('/^\d{9}(\d{3})?$/', $body) === 1,
            'LV' => preg_match('/^\d{11}$/', $body) === 1,
            'CY' => preg_match('/^\d{8}[A-Z]$/', $body) === 1,
            'MT' => preg_match('/^\d{8}$/', $body) === 1,
            'EL' => preg_match('/^\d{9}$/', $body) === 1,
            default => false,
        };
    }

    private static function vatGermany(string $digits): bool
    {
        $product = 10;

        for ($i = 0; $i < 8; $i++) {
            $sum = ((int) $digits[$i] + $product) % 10;

            if ($sum === 0) {
                $sum = 10;
            }

            $product = ($sum * 2) % 11;
        }

        $check = 11 - $product;

        if ($check === 10) {
            $check = 0;
        }

        return $check === (int) $digits[8];
    }

    private static function vatNetherlands(string $body): bool
    {
        $sum = 0;

        for ($i = 0; $i < 8; $i++) {
            $sum += (int) $body[$i] * (9 - $i);
        }

        return $sum % 11 === (int) $body[8];
    }

    private static function vatBritain(string $body): bool
    {
        $digits = substr($body, 0, 9);
        $weights = [8, 7, 6, 5, 4, 3, 2];
        $sum = 0;

        for ($i = 0; $i < 7; $i++) {
            $sum += (int) $digits[$i] * $weights[$i];
        }

        $check = (int) substr($digits, 7, 2);

        return ($sum + $check) % 97 === 0 || ($sum + $check + 55) % 97 === 0;
    }

    private static function vatFrance(string $body): bool
    {
        $key = substr($body, 0, 2);
        $siren = substr($body, 2);

        if (ctype_digit($key)) {
            return (int) $key === (12 + 3 * ((int) $siren % 97)) % 97;
        }

        // A key with letters uses a different scheme; accept on format...
        return true;
    }

    private static function digits(string $value): string
    {
        return preg_replace('/\D/', '', $value) ?? '';
    }

    private static function luhnSum(string $digits): int
    {
        $sum = 0;
        $double = false;

        for ($i = strlen($digits) - 1; $i >= 0; $i--) {
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

        return $sum;
    }

    /**
     * The remainder of a large numeric string divided by 97, taken piecewise.
     */
    private static function mod97(string $number): int
    {
        $numeric = '';

        foreach (str_split($number) as $character) {
            $numeric .= ctype_alpha($character) ? (string) (ord($character) - 55) : $character;
        }

        $remainder = 0;

        foreach (str_split($numeric, 7) as $chunk) {
            $remainder = (int) (($remainder).$chunk) % 97;
        }

        return $remainder;
    }

    /**
     * @param  array<int, int>  $weights
     */
    private static function mod11Check(string $digits, array $weights): int
    {
        $sum = 0;

        foreach ($weights as $i => $weight) {
            $sum += (int) $digits[$i] * $weight;
        }

        $check = 11 - ($sum % 11);

        return $check === 11 ? 0 : $check;
    }

    private static function plausibleDate(int $month, int $day): bool
    {
        // Swedish coordination numbers add 60 to the day...
        return $month >= 1 && $month <= 12 && (($day >= 1 && $day <= 31) || ($day >= 61 && $day <= 91));
    }
}
