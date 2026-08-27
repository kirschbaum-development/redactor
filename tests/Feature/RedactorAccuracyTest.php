<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;
use Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy;

function accuracyProfile(array $overrides = []): array
{
    return array_merge([
        'enabled' => true,
        'strategies' => [ShannonEntropyStrategy::class],
        'safe_keys' => [],
        'blocked_keys' => [],
        'patterns' => [],
        'replacement' => '[REDACTED]',
        'mark_redacted' => false,
        'track_redacted_keys' => false,
        'non_redactable_object_behavior' => 'preserve',
        'max_value_length' => null,
        'redact_large_objects' => false,
        'max_object_size' => 100,
        'shannon_entropy' => [
            'enabled' => true,
            'threshold' => 4.8,
            'min_length' => 20,
            'exclusion_patterns' => [],
        ],
    ], $overrides);
}

describe('Multibyte-correct entropy', function () {
    it('measures characters, not bytes', function () {
        $strategy = new ShannonEntropyStrategy;

        // Four distinct characters, evenly distributed: exactly 2 bits.
        // Measured over UTF-8 bytes each of these is three bytes, several of
        // them shared, which reports a quite different number.
        expect($strategy->calculateShannonEntropy('日本語能'))->toBeGreaterThan(1.9)
            ->and($strategy->calculateShannonEntropy('日本語能'))->toBeLessThan(2.1);
    });

    it('agrees with the ASCII case for four distinct characters', function () {
        $strategy = new ShannonEntropyStrategy;

        expect(round($strategy->calculateShannonEntropy('abcd'), 6))
            ->toBe(round($strategy->calculateShannonEntropy('日本語能'), 6));
    });

    it('reports zero for a single repeated multibyte character', function () {
        expect((new ShannonEntropyStrategy)->calculateShannonEntropy('日日日日日'))->toBe(0.0);
    });

    it('falls back to bytes for input that is not valid UTF-8', function () {
        $binary = "\xff\xfe\x00\x01\xff\xfe";

        expect((new ShannonEntropyStrategy)->calculateShannonEntropy($binary))->toBeGreaterThan(0.0);
    });

    it('counts min_length in characters', function () {
        // 10 characters, 30 bytes. Judged by strlen it clears a 20-character
        // minimum it should not reach.
        config()->set('redactor.profiles.accuracy', accuracyProfile([
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 0.5,
                'min_length' => 20,
                'exclusion_patterns' => [],
            ],
        ]));

        expect(app(Redactor::class)->redact(['t' => '日本語能力試験合格者'], 'accuracy'))
            ->toBe(['t' => '日本語能力試験合格者']);
    });
});

describe('Per-charset entropy thresholds', function () {
    it('catches a hex digest that a base64-shaped threshold misses', function () {
        // A 40-char SHA-1 tops out at 4.0 bits per character, so a 4.8
        // threshold can never fire on one however random it is.
        $digest = 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3';

        config()->set('redactor.profiles.accuracy', accuracyProfile());
        expect(app(Redactor::class)->redact(['h' => $digest], 'accuracy'))->toBe(['h' => $digest]);

        config()->set('redactor.profiles.accuracy', accuracyProfile([
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.8,
                'min_length' => 20,
                'charset_thresholds' => ['hex' => 3.0],
                'exclusion_patterns' => [],
            ],
        ]));
        expect(app(Redactor::class)->redact(['h' => $digest], 'accuracy'))->toBe(['h' => '[REDACTED]']);
    });

    it('leaves the configured threshold in charge when no charset matches', function () {
        config()->set('redactor.profiles.accuracy', accuracyProfile([
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.8,
                'min_length' => 20,
                'charset_thresholds' => ['hex' => 3.0],
                'exclusion_patterns' => [],
            ],
        ]));

        // Contains '-', so neither hex nor base64: judged at 4.8.
        expect(app(Redactor::class)->redact(['t' => 'sk-1234567890abcdef1234567890abcdef'], 'accuracy'))
            ->toBe(['t' => 'sk-1234567890abcdef1234567890abcdef']);
    });

    it('never silently overrides an explicitly configured threshold', function () {
        // No charset_thresholds configured means the single threshold applies
        // to every token, whatever alphabet it uses.
        config()->set('redactor.profiles.accuracy', accuracyProfile([
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 3.0,
                'min_length' => 20,
                'exclusion_patterns' => [],
            ],
        ]));

        expect(app(Redactor::class)->redact(['h' => 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3'], 'accuracy'))
            ->toBe(['h' => '[REDACTED]']);
    });

    it('identifies the alphabets it claims to', function () {
        $strategy = new class extends ShannonEntropyStrategy
        {
            public function charsetOf(string $s): ?string
            {
                return $this->detectCharset($s);
            }
        };

        expect($strategy->charsetOf('deadbeef0123'))->toBe('hex')
            ->and($strategy->charsetOf('YWJjZGVmZ2hpams='))->toBe('base64')
            ->and($strategy->charsetOf('abc-def_ghi'))->toBe('base64url')
            ->and($strategy->charsetOf('has spaces here'))->toBeNull();
    });
});

describe('Capture-group aware replacement', function () {
    it('keeps the label and replaces only the secret', function () {
        config()->set('redactor.profiles.capture', accuracyProfile([
            'strategies' => [RegexPatternsStrategy::class],
            'shannon_entropy' => ['enabled' => false],
            'patterns' => [
                'aws' => [
                    'pattern' => '/(aws_secret_access_key\s*=\s*)([A-Za-z0-9\/+]{40})/i',
                    'capture' => 2,
                ],
            ],
        ]));

        $secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

        expect(app(Redactor::class)->redact("aws_secret_access_key = {$secret}", 'capture'))
            ->toBe('aws_secret_access_key = [REDACTED]');
    });

    it('replaces the whole match when no capture group is declared', function () {
        config()->set('redactor.profiles.capture', accuracyProfile([
            'strategies' => [RegexPatternsStrategy::class],
            'shannon_entropy' => ['enabled' => false],
            'patterns' => ['aws' => '/aws_secret_access_key\s*=\s*[A-Za-z0-9\/+]{40}/i'],
        ]));

        expect(app(Redactor::class)->redact('aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'capture'))
            ->toBe('[REDACTED]');
    });

    it('combines capture groups with partial mode', function () {
        config()->set('redactor.profiles.capture', accuracyProfile([
            'strategies' => [RegexPatternsStrategy::class],
            'shannon_entropy' => ['enabled' => false],
            'patterns' => [
                'card' => ['pattern' => '/(card:\s*)(\d{16})/', 'capture' => 2, 'mode' => 'partial', 'keep' => 4],
            ],
        ]));

        expect(app(Redactor::class)->redact('card: 4111111111111111 ok', 'capture'))
            ->toBe('card: ************1111 ok');
    });

    it('falls back to the whole match when the group did not participate', function () {
        config()->set('redactor.profiles.capture', accuracyProfile([
            'strategies' => [RegexPatternsStrategy::class],
            'shannon_entropy' => ['enabled' => false],
            'patterns' => [
                'opt' => ['pattern' => '/secret(?:=(\w+))?/', 'capture' => 1],
            ],
        ]));

        expect(app(Redactor::class)->redact('bare secret here', 'capture'))
            ->toBe('bare [REDACTED] here');
    });
});

describe('Shipped file_scan patterns', function () {
    it('no longer flags every 40-character alphanumeric run as an AWS key', function () {
        // '/[0-9a-zA-Z\/+]{40}/' matched any SHA-1 digest, base64 chunk or
        // minified identifier in the codebase.
        $rule = RedactorConfig::fromConfig('file_scan')->patterns['aws_secret_key'];

        expect($rule->pattern)->not->toBe('/[0-9a-zA-Z\/+]{40}/')
            ->and($rule->capture)->toBe(2);

        // The rule alone no longer fires on a bare digest. (Entropy detection
        // may still flag it during a file scan - that is its job - but it is
        // no longer reported as an AWS credential.)
        expect(preg_match($rule->pattern, 'sha1 a94a8fe5ccb19ba61c4c0873d391e987982fbbd3caffe123'))
            ->toBe(0)
            ->and(preg_match($rule->pattern, 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'))
            ->toBe(0);
    });

    it('still catches an AWS secret key next to its label', function () {
        $result = app(Redactor::class)->redact(
            'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'file_scan'
        );

        expect($result)->toContain('[REDACTED]')
            ->and($result)->not->toContain('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
            ->and($result)->toContain('aws_secret_access_key');
    });

    it('keeps the password label while removing the value', function () {
        $result = app(Redactor::class)->redact('DB_PASSWORD=sup3rs3cret', 'file_scan');

        expect($result)->not->toContain('sup3rs3cret')
            ->and(strtolower($result))->toContain('password');
    });

    it('keeps the host while removing url credentials', function () {
        $result = app(Redactor::class)->redact('https://admin:hunter2@db.example.com/x', 'file_scan');

        expect($result)->not->toContain('hunter2')
            ->and($result)->toContain('db.example.com');
    });

    it('still catches unambiguous single-token secrets outright', function () {
        foreach ([
            'AKIAIOSFODNN7EXAMPLE',
            'ghp_1234567890abcdefghijklmnopqrstuvwxyz',
            'sk_test_1234567890abcdef1234567890abcdef',
        ] as $secret) {
            expect(app(Redactor::class)->redact("value: {$secret}", 'file_scan'))
                ->not->toContain($secret);
        }
    });
});

describe('The ASCII tokenise path matches the Unicode one', function () {
    function tokenProfile(): array
    {
        return accuracyProfile([
            'strategies' => [ShannonEntropyStrategy::class],
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 3.5,
                'min_length' => 12,
                'exclusion_patterns' => [],
            ],
        ]);
    }

    it('finds the same token in an ASCII value', function () {
        config()->set('redactor.profiles.tok', tokenProfile());

        expect(app(Redactor::class)->redact(['t' => 'key Zx7Qm4Kd9Rb2Vn6Tp end'], 'tok'))
            ->toBe(['t' => 'key [REDACTED] end']);
    });

    it('finds the same token when the value contains non-ASCII text', function () {
        config()->set('redactor.profiles.tok', tokenProfile());

        // Same secret, same neighbours, but the value is no longer ASCII - so
        // the /u pattern is used and must reach the same answer.
        expect(app(Redactor::class)->redact(['t' => 'клавиша Zx7Qm4Kd9Rb2Vn6Tp конец'], 'tok'))
            ->toBe(['t' => 'клавиша [REDACTED] конец']);
    });

    it('splits on a Unicode space, which the ASCII pattern would not', function () {
        config()->set('redactor.profiles.tok', tokenProfile());

        // U+00A0 between the words: with /u these are two tokens and only the
        // secret is replaced. Choosing the pattern per subject is what keeps
        // this correct.
        $value = "prefix\u{00A0}Zx7Qm4Kd9Rb2Vn6Tp";

        $result = app(Redactor::class)->redact(['t' => $value], 'tok');

        expect($result['t'])->toContain('prefix')
            ->and($result['t'])->toContain('[REDACTED]')
            ->and($result['t'])->not->toContain('Zx7Qm4Kd9Rb2Vn6Tp');
    });

    it('recognises ASCII and non-ASCII subjects correctly', function () {
        $strategy = new class extends ShannonEntropyStrategy
        {
            public function ascii(string $v): bool
            {
                return $this->isAscii($v);
            }
        };

        expect($strategy->ascii('plain ascii text'))->toBeTrue()
            ->and($strategy->ascii(''))->toBeTrue()
            ->and($strategy->ascii('café'))->toBeFalse()
            ->and($strategy->ascii("binary\xff\xfe"))->toBeFalse();
    });
});
