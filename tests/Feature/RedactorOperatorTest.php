<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Detection\Confidence;
use Kirschbaum\Redactor\Detection\Detection;
use Kirschbaum\Redactor\Operators\Operator;
use Kirschbaum\Redactor\Operators\OperatorContext;
use Kirschbaum\Redactor\Operators\OperatorRegistry;
use Kirschbaum\Redactor\Operators\OperatorSpec;
use Kirschbaum\Redactor\Operators\Surrogates\CharacterClassSurrogate;
use Kirschbaum\Redactor\Operators\Surrogates\CreditCardSurrogate;
use Kirschbaum\Redactor\Operators\Surrogates\EmailSurrogate;
use Kirschbaum\Redactor\Patterns\Validator;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;
use Kirschbaum\Redactor\Support\Pseudonymizer;

function detection(string $value, string $entity = 'generic'): Detection
{
    return new Detection(
        entity: $entity,
        rule: $entity,
        offset: 0,
        value: $value,
        confidence: Confidence::of(Confidence::HIGH),
    );
}

function operate(string $name, string $value, array $options = [], string $entity = 'generic'): string
{
    return (new OperatorRegistry)->get($name)->apply(
        detection($value, $entity),
        new OperatorContext('[REDACTED]', $options, Pseudonymizer::fromKey(testPseudonymizationKey())),
    );
}

function pseudoProfile(array $overrides = []): array
{
    return array_merge([
        'enabled' => true,
        'strategies' => [RegexPatternsStrategy::class],
        'safe_keys' => [],
        'blocked_keys' => [],
        'patterns' => [
            'email' => ['pattern' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/', 'entity' => 'email'],
        ],
        'operators' => ['default' => 'redact'],
        'replacement' => '[REDACTED]',
        'mark_redacted' => false,
        'track_redacted_keys' => false,
        'non_redactable_object_behavior' => 'preserve',
        'max_value_length' => null,
        'redact_large_objects' => false,
        'max_object_size' => 100,
        'shannon_entropy' => ['enabled' => false],
        'pseudonymization' => ['enabled' => true, 'key' => testPseudonymizationKey()],
    ], $overrides);
}

describe('Operators', function () {
    it('redacts, masks, keeps a tail and removes', function () {
        expect(operate('redact', 'hunter2'))->toBe('[REDACTED]')
            ->and(operate('mask', 'hunter2'))->toBe('*******')
            ->and(operate('partial', '4111111111111111', ['keep' => 4]))->toBe('************1111')
            ->and(operate('remove', 'hunter2'))->toBe('');
    });

    it('preserves a value while still reporting it', function () {
        expect(operate('preserve', 'hunter2'))->toBe('hunter2')
            ->and((new OperatorRegistry)->get('preserve')->isPreserving())->toBeTrue();
    });

    it('names the unknown operator rather than failing silently', function () {
        expect(fn () => (new OperatorRegistry)->get('teleport'))
            ->toThrow(\InvalidArgumentException::class, 'teleport');
    });

    it('accepts custom operators', function () {
        $registry = new OperatorRegistry;
        $registry->register('shout', new class implements Operator
        {
            public function apply(Detection $d, OperatorContext $c): string
            {
                return strtoupper($d->value);
            }

            public function isPreserving(): bool
            {
                return false;
            }
        });

        expect($registry->get('shout')->apply(detection('quiet'), new OperatorContext('[R]')))->toBe('QUIET');
    });
});

describe('Operator configuration shapes', function () {
    it('accepts a bare name, a name with options, and an explicit key', function () {
        expect(OperatorSpec::parse('partial', 'p')->name)->toBe('partial')
            ->and(OperatorSpec::parse(['partial' => ['keep' => 6]], 'p')->options)->toBe(['keep' => 6])
            ->and(OperatorSpec::parse(['operator' => 'partial', 'keep' => 6], 'p')->name)->toBe('partial')
            ->and(OperatorSpec::parse(['operator' => 'partial', 'keep' => 6], 'p')->options)->toBe(['keep' => 6]);
    });

    it('rejects a definition that names no operator', function () {
        expect(fn () => OperatorSpec::parse([], 'profiles.x.operators.y'))
            ->toThrow(\InvalidArgumentException::class, 'profiles.x.operators.y');
    });
});

describe('Operator precedence', function () {
    function precedenceProfile(array $patterns, array $operators): array
    {
        return pseudoProfile(['patterns' => $patterns, 'operators' => $operators]);
    }

    it('applies operators.default to a rule that asked for nothing', function () {
        // `mode` defaults to replace, so a rule can always produce an operator
        // spec - which is not the same as having chosen one. Treating the
        // default as a choice made operators.default unreachable for anything
        // found by a pattern, silently.
        config()->set('redactor.profiles.prec', precedenceProfile(
            ['digits' => '/\d+/'],
            ['default' => 'mask'],
        ));

        expect(app(Redactor::class)->redact('a1b22c', 'prec'))->toBe('a*b**c');
    });

    it('lets a rule that did choose a mode outrank the default', function () {
        config()->set('redactor.profiles.prec', precedenceProfile(
            ['digits' => ['pattern' => '/\d+/', 'mode' => 'remove']],
            ['default' => 'mask'],
        ));

        expect(app(Redactor::class)->redact('a1b22c', 'prec'))->toBe('abc');
    });

    it('lets a rule with an explicit operator outrank the default', function () {
        config()->set('redactor.profiles.prec', precedenceProfile(
            ['digits' => ['pattern' => '/\d+/', 'operator' => 'remove']],
            ['default' => 'mask'],
        ));

        expect(app(Redactor::class)->redact('a1b22c', 'prec'))->toBe('abc');
    });

    it('lets the entity outrank both the rule and the default', function () {
        config()->set('redactor.profiles.prec', precedenceProfile(
            ['digits' => ['pattern' => '/\d+/', 'entity' => 'num', 'mode' => 'remove']],
            ['default' => 'mask', 'num' => 'redact'],
        ));

        expect(app(Redactor::class)->redact('a1b22c', 'prec'))->toBe('a[REDACTED]b[REDACTED]c');
    });

    it('falls back to redaction when no operator is configured anywhere', function () {
        config()->set('redactor.profiles.prec', precedenceProfile(['digits' => '/\d+/'], []));

        expect(app(Redactor::class)->redact('a1b22c', 'prec'))->toBe('a[REDACTED]b[REDACTED]c');
    });
});

describe('Deterministic pseudonymization', function () {
    it('maps the same value to the same surrogate every time', function () {
        $a = operate('surrogate', 'alice@customer.com', [], 'email');
        $b = operate('surrogate', 'alice@customer.com', [], 'email');

        expect($a)->toBe($b);
    });

    it('maps different values to different surrogates', function () {
        expect(operate('surrogate', 'alice@customer.com', [], 'email'))
            ->not->toBe(operate('surrogate', 'bob@customer.com', [], 'email'));
    });

    it('normalises case and whitespace so the mapping stays joinable', function () {
        // The same person written two ways has to land on the same surrogate,
        // or grouping by it silently double-counts.
        expect(operate('surrogate', ' Alice@Customer.COM ', [], 'email'))
            ->toBe(operate('surrogate', 'alice@customer.com', [], 'email'));
    });

    it('produces different surrogates under a different key', function () {
        $withKeyA = (new OperatorRegistry)->get('surrogate')->apply(
            detection('alice@customer.com', 'email'),
            new OperatorContext('[R]', [], Pseudonymizer::fromKey(testPseudonymizationKey())),
        );

        $withKeyB = (new OperatorRegistry)->get('surrogate')->apply(
            detection('alice@customer.com', 'email'),
            new OperatorContext('[R]', [], Pseudonymizer::fromKey('a-completely-different-key-also-long-enough')),
        );

        expect($withKeyA)->not->toBe($withKeyB);
    });

    it('falls back to plain redaction when no key is available', function () {
        // An unkeyed surrogate would look joinable and silently not be.
        $result = (new OperatorRegistry)->get('surrogate')->apply(
            detection('alice@customer.com', 'email'),
            new OperatorContext('[REDACTED]', [], null),
        );

        expect($result)->toBe('[REDACTED]');
    });

    it('rejects a key too short to be worth having', function () {
        expect(fn () => Pseudonymizer::fromKey('short'))
            ->toThrow(\RuntimeException::class, 'at least');
    });

    it('derives a key from APP_KEY without using it directly', function () {
        $derived = Pseudonymizer::derivedFrom('base64:'.base64_encode(str_repeat('k', 32)));
        $direct = Pseudonymizer::fromKey(str_repeat('k', 32));

        expect($derived->digest('email', 'a@b.com'))->not->toBe($direct->digest('email', 'a@b.com'));
    });

    it('emits a stable labelled token in hash mode', function () {
        $token = operate('hash', 'alice@customer.com', [], 'email');

        expect($token)->toStartWith('[email:')
            ->and($token)->toEndWith(']')
            ->and($token)->toBe(operate('hash', 'alice@customer.com', [], 'email'))
            ->and($token)->not->toContain('alice');
    });
});

describe('Format-preserving surrogates', function () {
    it('keeps an email parseable and its domain intact', function () {
        $result = operate('surrogate', 'alice@customer.com', ['preserve_domain' => true], 'email');

        expect($result)->toEndWith('@customer.com')
            ->and($result)->not->toContain('alice')
            ->and(filter_var($result, FILTER_VALIDATE_EMAIL))->not->toBeFalse();
    });

    it('replaces the domain with a guaranteed-unroutable one when asked', function () {
        // RFC 2606 reserves .invalid, so a surrogate that escapes into a mail
        // queue bounces rather than reaching a stranger.
        expect(operate('surrogate', 'alice@customer.com', ['preserve_domain' => false], 'email'))
            ->toEndWith('@example.invalid');
    });

    it('keeps a card Luhn-valid, same length, same grouping', function () {
        $result = operate('surrogate', '4111 1111 1111 1111', ['preserve_bin' => 6], 'credit_card');

        expect($result)->not->toBe('4111 1111 1111 1111')
            ->and(strlen($result))->toBe(19)
            ->and($result)->toStartWith('4111 11')
            ->and(Validator::luhn($result))->toBeTrue()
            ->and(preg_match('/^\d{4} \d{4} \d{4} \d{4}$/', $result))->toBe(1);
    });

    it('preserves character classes and separators for anything else', function () {
        $result = (new CharacterClassSurrogate)->generate(
            'sk_live_4eC39HqLyj',
            Pseudonymizer::fromKey(testPseudonymizationKey())->random('generic', 'sk_live_4eC39HqLyj'),
            ['preserve_prefix' => 8],
        );

        expect($result)->toStartWith('sk_live_')
            ->and(strlen($result))->toBe(strlen('sk_live_4eC39HqLyj'))
            ->and($result)->not->toBe('sk_live_4eC39HqLyj');

        // Same shape, character class for character class.
        $original = 'sk_live_4eC39HqLyj';
        for ($i = 0; $i < strlen($original); $i++) {
            expect(ctype_digit($result[$i]))->toBe(ctype_digit($original[$i]))
                ->and(ctype_upper($result[$i]))->toBe(ctype_upper($original[$i]))
                ->and(ctype_lower($result[$i]))->toBe(ctype_lower($original[$i]));
        }
    });

    it('preserves digit positions and punctuation in a structured value', function () {
        $original = '2024-01-15T09:31:00Z';

        $result = (new CharacterClassSurrogate)->generate(
            $original,
            Pseudonymizer::fromKey(testPseudonymizationKey())->random('generic', $original),
        );

        // The contract is character classes, not semantics: it does not know
        // this is a timestamp, so the 'T' and 'Z' are letters like any other
        // and get replaced. Digit positions, length and punctuation survive.
        expect(preg_match('/^\d{4}-\d{2}-\d{2}[A-Z]\d{2}:\d{2}:\d{2}[A-Z]$/', $result))->toBe(1)
            ->and($result)->not->toBe($original)
            ->and(strlen($result))->toBe(strlen($original));
    });

    it('picks the most specific generator for the entity', function () {
        expect((new EmailSurrogate)->supports('email', 'a@b.com'))->toBeTrue()
            ->and((new EmailSurrogate)->supports('generic', 'no-at-sign'))->toBeFalse()
            ->and((new CreditCardSurrogate)->supports('credit_card', '4111111111111111'))->toBeTrue()
            ->and((new CreditCardSurrogate)->supports('generic', 'abc'))->toBeFalse()
            ->and((new CharacterClassSurrogate)->supports('anything', 'at all'))->toBeTrue();
    });
});

describe('Pseudonymization end to end', function () {
    it('keeps a log line joinable through the redactor', function () {
        config()->set('redactor.profiles.pseudo', pseudoProfile([
            'operators' => ['default' => 'redact', 'email' => ['surrogate' => ['preserve_domain' => true]]],
        ]));

        $first = app(Redactor::class)->redact('login from alice@customer.com ok', 'pseudo');
        $second = app(Redactor::class)->redact('logout for alice@customer.com ok', 'pseudo');

        preg_match('/(\S+@customer\.com)/', $first, $a);
        preg_match('/(\S+@customer\.com)/', $second, $b);

        expect($a[1] ?? 'x')->toBe($b[1] ?? 'y')
            ->and($first)->not->toContain('alice')
            ->and($first)->toStartWith('login from ');
    });

    it('lets one entity be pseudonymised while another is redacted', function () {
        config()->set('redactor.profiles.pseudo', pseudoProfile([
            'patterns' => [
                'email' => ['pattern' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/', 'entity' => 'email'],
                'card' => ['pattern' => '/\b\d{16}\b/', 'entity' => 'credit_card'],
            ],
            'operators' => [
                'default' => 'redact',
                'email' => 'surrogate',
                'credit_card' => 'redact',
            ],
        ]));

        $result = app(Redactor::class)->redact('a@b.com paid with 4111111111111111', 'pseudo');

        expect($result)->toContain('@b.com')
            ->and($result)->not->toContain('a@b.com')
            ->and($result)->toContain('[REDACTED]');
    });

    it('honours the shipped observability profile', function () {
        config()->set('redactor.pseudonymization', ['enabled' => true, 'key' => testPseudonymizationKey()]);

        $result = app(Redactor::class)->redact([
            'message' => 'checkout by alice@customer.com from 203.0.113.9',
            'trace_id' => 'abc-123',
        ], 'observability');

        expect($result['trace_id'])->toBe('abc-123')
            ->and($result['message'])->toStartWith('checkout by ')
            ->and($result['message'])->not->toContain('alice@customer.com')
            ->and($result['message'])->toContain('@customer.com')
            ->and($result['message'])->not->toContain('203.0.113.9');
    });

    it('degrades to redaction rather than emitting an unkeyed surrogate', function () {
        config()->set('redactor.profiles.pseudo', pseudoProfile([
            'operators' => ['default' => 'redact', 'email' => 'surrogate'],
            'pseudonymization' => ['enabled' => false],
        ]));

        expect(app(Redactor::class)->redact('mail a@b.com now', 'pseudo'))
            ->toBe('mail [REDACTED] now');
    });
});
