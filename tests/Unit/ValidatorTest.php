<?php

declare(strict_types=1);

use Kirschbaum\Redactor\Patterns\Validator;

describe('National identifier validators', function (): void {
    it('checks NHS numbers by their mod-11 digit', function (): void {
        expect(Validator::nhs('915 229 6008'))->toBeTrue()
            ->and(Validator::nhs('5114026240'))->toBeTrue()
            ->and(Validator::nhs('1234567890'))->toBeFalse()
            ->and(Validator::nhs('0988416930'))->toBeFalse()
            ->and(Validator::nhs('12345'))->toBeFalse();
    });

    it('checks Dutch BSNs by the eleven-proof', function (): void {
        expect(Validator::bsn('283194443'))->toBeTrue()
            ->and(Validator::bsn('123456789'))->toBeFalse()
            ->and(Validator::bsn('12345678'))->toBeFalse();
    });

    it('checks German tax identification numbers', function (): void {
        expect(Validator::steuerId('72 096 139 541'))->toBeTrue()
            ->and(Validator::steuerId('78325422090'))->toBeTrue()
            ->and(Validator::steuerId('72096139542'))->toBeFalse()
            ->and(Validator::steuerId('02096139541'))->toBeFalse()
            ->and(Validator::steuerId('12345678901'))->toBeFalse()
            ->and(Validator::steuerId('11223456789'))->toBeFalse()
            ->and(Validator::steuerId('11114567890'))->toBeFalse();
    });

    it('checks French NIRs including Corsican departments', function (): void {
        expect(Validator::nir('1 96 04 20 350 020 61'))->toBeTrue()
            ->and(Validator::nir('264122A44815913'))->toBeTrue()
            ->and(Validator::nir('1 96 04 20 350 020 62'))->toBeFalse()
            ->and(Validator::nir('3 96 04 20 350 020 61'))->toBeFalse();
    });

    it('checks Spanish DNI and NIE letters', function (): void {
        expect(Validator::dni('68334472T'))->toBeTrue()
            ->and(Validator::dni('68334472-T'))->toBeTrue()
            ->and(Validator::dni('x6732518g'))->toBeTrue()
            ->and(Validator::dni('12345678A'))->toBeFalse()
            ->and(Validator::dni('X6732518A'))->toBeFalse()
            ->and(Validator::dni('1234A'))->toBeFalse();
    });

    it('checks Italian fiscal codes', function (): void {
        expect(Validator::codiceFiscale('RSSMRA85T10A562S'))->toBeTrue()
            ->and(Validator::codiceFiscale('rssmra85t10a562s'))->toBeTrue()
            ->and(Validator::codiceFiscale('RSSMRA85T10A562T'))->toBeFalse()
            ->and(Validator::codiceFiscale('RSSMRA85X10A562S'))->toBeFalse();
    });

    it('checks Belgian national numbers for both centuries', function (): void {
        expect(Validator::belgianNationalNumber('54.04.11-613.25'))->toBeTrue()
            ->and(Validator::belgianNationalNumber('13.07.16-349.07'))->toBeTrue()
            ->and(Validator::belgianNationalNumber('54.04.11-613.26'))->toBeFalse()
            ->and(Validator::belgianNationalNumber('54.04.11'))->toBeFalse();
    });

    it('checks Swedish personal numbers in both lengths and coordination form', function (): void {
        expect(Validator::personnummer('600112-7239'))->toBeTrue()
            ->and(Validator::personnummer('19600112-7239'))->toBeTrue()
            ->and(Validator::personnummer('610485-0869'))->toBeTrue()
            ->and(Validator::personnummer('600112-7238'))->toBeFalse()
            ->and(Validator::personnummer('1694600000'))->toBeFalse()
            ->and(Validator::personnummer('60011'))->toBeFalse();
    });

    it('checks Norwegian identity numbers with both control digits', function (): void {
        expect(Validator::fodselsnummer('25054326869'))->toBeTrue()
            ->and(Validator::fodselsnummer('27089492705'))->toBeTrue()
            ->and(Validator::fodselsnummer('25054326868'))->toBeFalse()
            ->and(Validator::fodselsnummer('25054326879'))->toBeFalse()
            ->and(Validator::fodselsnummer('2505432686'))->toBeFalse();
    });

    it('checks Canadian SINs and Australian TFNs', function (): void {
        expect(Validator::sin('965-232-432'))->toBeTrue()
            ->and(Validator::sin('123-456-789'))->toBeFalse()
            ->and(Validator::sin('065-232-432'))->toBeFalse()
            ->and(Validator::sin('12345678'))->toBeFalse()
            ->and(Validator::tfn('261 158 631'))->toBeTrue()
            ->and(Validator::tfn('75817404'))->toBeTrue()
            ->and(Validator::tfn('123 456 789'))->toBeFalse()
            ->and(Validator::tfn('1234567'))->toBeFalse();
    });
});

describe('VAT validation', function (): void {
    it('verifies the checksums it knows', function (): void {
        foreach (['DE869428760', 'DE246246459', 'NL514465888B07', 'GB436083107', 'GB729304771', 'GB198679577001', 'IT55679497721', 'FR50786240626', 'FRAB123456789', 'BE0190125740', 'SE213467230801'] as $valid) {
            expect(Validator::vat($valid))->toBeTrue($valid);
        }

        foreach (['DE000000000', 'NL123456789B01', 'GB123456789', 'IT00000000001', 'FR00786240626', 'BE0190125741', 'SE213467230802', 'SE213467230901'] as $invalid) {
            expect(Validator::vat($invalid))->toBeFalse($invalid);
        }
    });

    it('accepts the rest of the union on format', function (): void {
        foreach (['ES B12345674', 'ATU12345678', 'DK12345678', 'FI12345678', 'IE1234567FA', 'PL1234567890', 'PT123456789', 'LU12345678', 'CZ12345678', 'HU12345678', 'RO12', 'SK1234567890', 'SI12345678', 'HR12345678901', 'BG123456789', 'EE123456789', 'LT123456789012', 'LV12345678901', 'CY12345678A', 'MT12345678', 'EL123456789'] as $valid) {
            expect(Validator::vat($valid))->toBeTrue($valid);
        }

        expect(Validator::vat('ES12345'))->toBeFalse()
            ->and(Validator::vat('CY12345678'))->toBeFalse()
            ->and(Validator::vat('XX12345678'))->toBeFalse()
            ->and(Validator::vat('12345678'))->toBeFalse();
    });
});

describe('Validator registry', function (): void {
    it('knows its names and accepts custom validators', function (): void {
        expect(Validator::exists('luhn'))->toBeTrue()
            ->and(Validator::exists('nope'))->toBeFalse()
            ->and(Validator::passes('nope', 'x'))->toBeTrue();

        Validator::extend('even_length', fn (string $v): bool => strlen($v) % 2 === 0);

        expect(Validator::exists('even_length'))->toBeTrue()
            ->and(Validator::passes('even_length', 'ab'))->toBeTrue()
            ->and(Validator::passes('even_length', 'abc'))->toBeFalse();
    });
});
