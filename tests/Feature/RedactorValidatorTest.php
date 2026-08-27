<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Patterns\Validator;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;

function validatorProfile(array $patterns): array
{
    return [
        'enabled' => true,
        'strategies' => [RegexPatternsStrategy::class],
        'safe_keys' => [],
        'blocked_keys' => [],
        'patterns' => $patterns,
        'replacement' => '[REDACTED]',
        'mark_redacted' => false,
        'track_redacted_keys' => false,
        'non_redactable_object_behavior' => 'preserve',
        'max_value_length' => null,
        'redact_large_objects' => false,
        'max_object_size' => 100,
        'shannon_entropy' => ['enabled' => false],
    ];
}

describe('Luhn', function () {
    it('accepts real card numbers', function () {
        foreach ([
            '4111111111111111',   // Visa test
            '5500005555555559',   // Mastercard test
            '378282246310005',    // Amex test
            '6011111111111117',   // Discover test
            '4111 1111 1111 1111',
            '4111-1111-1111-1111',
        ] as $card) {
            expect(Validator::luhn($card))->toBeTrue("expected {$card} to pass Luhn");
        }
    });

    it('rejects numbers of the right shape that are not cards', function () {
        foreach ([
            '4111111111111112',   // one digit off
            '1234567890123456',
            '2024010112000001',   // concatenated timestamp
            '9999999999999999',
        ] as $notCard) {
            expect(Validator::luhn($notCard))->toBeFalse("expected {$notCard} to fail Luhn");
        }
    });

    it('rejects runs that are too short or too long to be a card', function () {
        expect(Validator::luhn('12345678901'))->toBeFalse()
            ->and(Validator::luhn('12345678901234567890'))->toBeFalse();
    });
});

describe('IBAN', function () {
    it('accepts valid IBANs', function () {
        foreach ([
            'GB82WEST12345698765432',
            'DE89370400440532013000',
            'FR1420041010050500013M02606',
            'GB82 WEST 1234 5698 7654 32',
        ] as $iban) {
            expect(Validator::iban($iban))->toBeTrue("expected {$iban} to pass mod-97");
        }
    });

    it('rejects a wrong check digit', function () {
        expect(Validator::iban('GB82WEST12345698765431'))->toBeFalse()
            ->and(Validator::iban('DE89370400440532013001'))->toBeFalse();
    });

    it('rejects malformed input', function () {
        expect(Validator::iban('12345678901234567'))->toBeFalse()
            ->and(Validator::iban('GB'))->toBeFalse();
    });
});

describe('SSN', function () {
    it('accepts issuable numbers', function () {
        expect(Validator::ssn('123-45-6789'))->toBeTrue()
            ->and(Validator::ssn('123456789'))->toBeTrue();
    });

    it('rejects never-issued area, group and serial values', function () {
        expect(Validator::ssn('000-45-6789'))->toBeFalse()
            ->and(Validator::ssn('666-45-6789'))->toBeFalse()
            ->and(Validator::ssn('900-45-6789'))->toBeFalse()
            ->and(Validator::ssn('123-00-6789'))->toBeFalse()
            ->and(Validator::ssn('123-45-0000'))->toBeFalse();
    });

    it('rejects the wrong number of digits', function () {
        expect(Validator::ssn('12345678'))->toBeFalse()
            ->and(Validator::ssn('1234567890'))->toBeFalse();
    });
});

describe('Validators inside redaction', function () {
    it('redacts a valid card and leaves an invalid lookalike alone', function () {
        config()->set('redactor.profiles.validated', validatorProfile([
            'card' => [
                'pattern' => '/\b(?:\d[ -]*?){13,16}\b/',
                'validator' => 'luhn',
                'mode' => 'partial',
                'keep' => 4,
            ],
        ]));

        expect(app(Redactor::class)->redact('card 4111111111111111 ok', 'validated'))
            ->toBe('card ************1111 ok');

        // An order number of the same shape survives.
        expect(app(Redactor::class)->redact('order 2024010112000001 ok', 'validated'))
            ->toBe('order 2024010112000001 ok');
    });

    it('does not mark a payload redacted when every match failed validation', function () {
        config()->set('redactor.profiles.validated', validatorProfile([
            'card' => ['pattern' => '/\b\d{16}\b/', 'validator' => 'luhn'],
        ]));

        $result = app(Redactor::class)->redactWithMetadata(['n' => '1234567890123456'], 'validated');

        expect($result->wasRedacted)->toBeFalse()
            ->and($result->value)->toBe(['n' => '1234567890123456']);
    });

    it('redacts the valid matches and leaves the invalid ones in the same string', function () {
        config()->set('redactor.profiles.validated', validatorProfile([
            'card' => ['pattern' => '/\b\d{16}\b/', 'validator' => 'luhn'],
        ]));

        expect(app(Redactor::class)->redact('good 4111111111111111 bad 1234567890123456', 'validated'))
            ->toBe('good [REDACTED] bad 1234567890123456');
    });

    it('validates the capture group, not the surrounding context', function () {
        config()->set('redactor.profiles.validated', validatorProfile([
            'card' => ['pattern' => '/(card:\s*)(\d{16})/', 'capture' => 2, 'validator' => 'luhn'],
        ]));

        expect(app(Redactor::class)->redact('card: 4111111111111111', 'validated'))
            ->toBe('card: [REDACTED]')
            ->and(app(Redactor::class)->redact('card: 1234567890123456', 'validated'))
            ->toBe('card: 1234567890123456');
    });

    it('applies validation in full mode too', function () {
        config()->set('redactor.profiles.validated', validatorProfile([
            'card' => ['pattern' => '/\b\d{16}\b/', 'validator' => 'luhn', 'mode' => 'full'],
        ]));

        expect(app(Redactor::class)->redact('n 1234567890123456', 'validated'))
            ->toBe('n 1234567890123456')
            ->and(app(Redactor::class)->redact('n 4111111111111111', 'validated'))
            ->toBe('[REDACTED]');
    });

    it('rejects an unknown validator name in config', function () {
        config()->set('redactor.profiles.validated', validatorProfile([
            'card' => ['pattern' => '/\d+/', 'validator' => 'vibes'],
        ]));

        expect(fn () => RedactorConfig::fromConfig('validated'))
            ->toThrow(\InvalidArgumentException::class, 'patterns.card.validator');
    });
});

describe('Shipped profiles use validators', function () {
    it('no longer flags an order number as a credit card', function () {
        $result = app(Redactor::class)->redact(['note' => 'order 2024010112000001 shipped'], 'default');

        expect($result['note'])->toBe('order 2024010112000001 shipped');
    });

    it('still redacts a real card in the default profile', function () {
        $result = app(Redactor::class)->redact(['note' => 'paid with 4111111111111111'], 'default');

        expect($result['note'])->not->toContain('4111111111111111')
            ->and($result['note'])->toContain('1111');
    });

    it('no longer flags 000-00-0000 as an SSN', function () {
        $result = app(Redactor::class)->redact(['note' => 'placeholder 000-00-0000'], 'default');

        expect($result['note'])->toBe('placeholder 000-00-0000');
    });

    it('redacts a valid IBAN', function () {
        $result = app(Redactor::class)->redact(['note' => 'pay GB82WEST12345698765432 now'], 'default');

        expect($result['note'])->not->toContain('GB82WEST12345698765432');
    });
});
