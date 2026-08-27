<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Patterns\PatternRule;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Strategies\BlockedKeysStrategy;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;
use Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy;

function spanProfile(array $patterns, array $overrides = []): array
{
    return array_merge([
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
    ], $overrides);
}

const EMAIL = '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/';

describe('Span-level replacement', function () {
    it('replaces only the match and keeps the surrounding text', function () {
        config()->set('redactor.profiles.span', spanProfile(['email' => EMAIL]));

        // Previously the entire message became "[REDACTED]", which made the
        // package unusable in the log pipeline it ships an integration for.
        expect(app(Redactor::class)->redact(['msg' => 'User bob@example.com placed order 123'], 'span'))
            ->toBe(['msg' => 'User [REDACTED] placed order 123']);
    });

    it('replaces a bare string passed straight to redact()', function () {
        config()->set('redactor.profiles.span', spanProfile(['email' => EMAIL]));

        expect(app(Redactor::class)->redact('User bob@example.com placed order 123', 'span'))
            ->toBe('User [REDACTED] placed order 123');
    });

    it('replaces every occurrence, not just the first', function () {
        config()->set('redactor.profiles.span', spanProfile(['email' => EMAIL]));

        expect(app(Redactor::class)->redact('a@x.com cc b@y.com and c@z.com', 'span'))
            ->toBe('[REDACTED] cc [REDACTED] and [REDACTED]');
    });

    it('applies several rules to the same string', function () {
        config()->set('redactor.profiles.span', spanProfile([
            'email' => EMAIL,
            'ssn' => '/\b\d{3}-\d{2}-\d{4}\b/',
        ]));

        expect(app(Redactor::class)->redact('bob@x.com / 123-45-6789 / keep', 'span'))
            ->toBe('[REDACTED] / [REDACTED] / keep');
    });

    it('leaves a clean string completely untouched', function () {
        config()->set('redactor.profiles.span', spanProfile(['email' => EMAIL]));

        expect(app(Redactor::class)->redact('nothing sensitive here at all', 'span'))
            ->toBe('nothing sensitive here at all');
    });

    it('marks the payload redacted only when something matched', function () {
        config()->set('redactor.profiles.span', spanProfile(['email' => EMAIL], [
            'mark_redacted' => true,
            'track_redacted_keys' => true,
        ]));

        $hit = app(Redactor::class)->redact(['msg' => 'ping bob@x.com'], 'span');
        $miss = app(Redactor::class)->redact(['msg' => 'ping nobody'], 'span');

        expect($hit)->toHaveKey('_redacted')
            ->and($hit['_redacted_keys'])->toBe(['msg'])
            ->and($miss)->not->toHaveKey('_redacted');
    });
});

describe('Pattern rule modes', function () {
    it('masks the match while preserving its length', function () {
        config()->set('redactor.profiles.span', spanProfile([
            'email' => ['pattern' => EMAIL, 'mode' => 'mask'],
        ]));

        expect(app(Redactor::class)->redact('to bob@x.com now', 'span'))
            ->toBe('to ********* now'); // bob@x.com is 9 characters
    });

    it('keeps the trailing characters in partial mode', function () {
        config()->set('redactor.profiles.span', spanProfile([
            'card' => ['pattern' => '/\b\d{16}\b/', 'mode' => 'partial', 'keep' => 4],
        ]));

        expect(app(Redactor::class)->redact('card 4111111111111111 ok', 'span'))
            ->toBe('card ************1111 ok');
    });

    it('masks everything when the match is no longer than keep', function () {
        config()->set('redactor.profiles.span', spanProfile([
            'pin' => ['pattern' => '/\b\d{4}\b/', 'mode' => 'partial', 'keep' => 4],
        ]));

        expect(app(Redactor::class)->redact('pin 1234 ok', 'span'))
            ->toBe('pin **** ok');
    });

    it('deletes the match in remove mode', function () {
        config()->set('redactor.profiles.span', spanProfile([
            'email' => ['pattern' => EMAIL, 'mode' => 'remove'],
        ]));

        expect(app(Redactor::class)->redact('to bob@x.com now', 'span'))
            ->toBe('to  now');
    });

    it('still supports replacing the whole value in full mode', function () {
        config()->set('redactor.profiles.span', spanProfile([
            'email' => ['pattern' => EMAIL, 'mode' => 'full'],
        ]));

        expect(app(Redactor::class)->redact('to bob@x.com now', 'span'))
            ->toBe('[REDACTED]');
    });

    it('honours a custom mask character', function () {
        config()->set('redactor.profiles.span', spanProfile([
            'card' => ['pattern' => '/\b\d{16}\b/', 'mode' => 'partial', 'keep' => 4, 'mask_character' => '#'],
        ]));

        expect(app(Redactor::class)->redact('4111111111111111', 'span'))
            ->toBe('############1111');
    });

    it('rejects an unknown mode instead of silently replacing', function () {
        config()->set('redactor.profiles.span', spanProfile([
            'email' => ['pattern' => EMAIL, 'mode' => 'obliterate'],
        ]));

        expect(fn () => RedactorConfig::fromConfig('span'))
            ->toThrow(\InvalidArgumentException::class, 'patterns.email.mode');
    });

    it('rejects a rule with no pattern', function () {
        config()->set('redactor.profiles.span', spanProfile([
            'email' => ['mode' => 'mask'],
        ]));

        expect(fn () => RedactorConfig::fromConfig('span'))
            ->toThrow(\InvalidArgumentException::class, 'patterns.email');
    });

    it('still drops an uncompilable pattern rather than failing the profile', function () {
        config()->set('redactor.profiles.span', spanProfile([
            'ok' => EMAIL,
            'broken' => '/[unclosed/',
        ]));

        expect(array_keys(RedactorConfig::fromConfig('span')->patterns))->toBe(['ok']);
    });

    it('counts characters, not bytes, when masking', function () {
        $rule = new PatternRule(name: 't', pattern: '//', mode: PatternRule::MODE_MASK);

        expect($rule->substitute('héllo', '[R]'))->toBe('*****');
    });
});

describe('Entropy redaction inside a larger string', function () {
    it('replaces only the high-entropy token', function () {
        config()->set('redactor.profiles.entropy_span', spanProfile([], [
            'strategies' => [ShannonEntropyStrategy::class],
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.0,
                'min_length' => 20,
                'exclusion_patterns' => [],
            ],
        ]));

        $result = app(Redactor::class)->redact(
            ['msg' => 'deploy failed using key Zx7Qm4Kd9Rb2Vn6Tp1Ws8Yc3Hf please rotate'],
            'entropy_span'
        );

        expect($result['msg'])->toBe('deploy failed using key [REDACTED] please rotate');
    });

    it('still replaces the whole value when it is a single token', function () {
        config()->set('redactor.profiles.entropy_span', spanProfile([], [
            'strategies' => [ShannonEntropyStrategy::class],
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.0,
                'min_length' => 20,
                'exclusion_patterns' => [],
            ],
        ]));

        expect(app(Redactor::class)->redact(['k' => 'Zx7Qm4Kd9Rb2Vn6Tp1Ws8Yc3Hf'], 'entropy_span'))
            ->toBe(['k' => '[REDACTED]']);
    });
});

describe('Strategy chaining', function () {
    it('lets entropy inspect what the regex rules left standing', function () {
        // The email matches first. Before chaining existed, the regex strategy
        // ended the chain and the API key next to it survived.
        config()->set('redactor.profiles.chained', spanProfile(['email' => EMAIL], [
            'strategies' => [RegexPatternsStrategy::class, ShannonEntropyStrategy::class],
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.0,
                'min_length' => 20,
                'exclusion_patterns' => [],
            ],
        ]));

        $result = app(Redactor::class)->redact(
            ['msg' => 'from bob@example.com key Zx7Qm4Kd9Rb2Vn6Tp1Ws8Yc3Hf end'],
            'chained'
        );

        expect($result['msg'])->toBe('from [REDACTED] key [REDACTED] end');
    });

    it('stops the chain at a strategy that replaces the whole value', function () {
        config()->set('redactor.profiles.terminal', spanProfile(['email' => EMAIL], [
            'strategies' => [
                BlockedKeysStrategy::class,
                RegexPatternsStrategy::class,
            ],
            'blocked_keys' => ['secret_note'],
        ]));

        expect(app(Redactor::class)->redact(['secret_note' => 'bob@example.com'], 'terminal'))
            ->toBe(['secret_note' => '[REDACTED]']);
    });
});
