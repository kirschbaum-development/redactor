<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Patterns\PatternRule;
use Kirschbaum\Redactor\Patterns\Validator;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Strategies\LargeObjectStrategy;
use Kirschbaum\Redactor\Strategies\LargeStringStrategy;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;
use Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy;

/**
 * Every threshold in this package is a redaction decision, so the exact point
 * at which it flips matters: one off-by-one is the difference between a secret
 * being caught and being emitted. These pin each boundary from both sides.
 *
 * Mutation testing is what surfaced the gap - the suite covered the thresholds
 * comfortably but never their edges, so `>` could become `>=` without a single
 * test noticing.
 */
function boundaryProfile(array $overrides = []): array
{
    return array_merge([
        'enabled' => true,
        'strategies' => [LargeObjectStrategy::class, LargeStringStrategy::class],
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
        'shannon_entropy' => ['enabled' => false],
    ], $overrides);
}

function arrayOf(int $size): array
{
    return array_fill_keys(array_map(fn (int $i) => "k{$i}", range(1, $size)), 'v');
}

describe('max_object_size boundary', function () {
    beforeEach(function () {
        config()->set('redactor.profiles.boundary', boundaryProfile([
            'redact_large_objects' => true,
            'max_object_size' => 10,
        ]));
    });

    it('leaves an array of exactly max_object_size alone', function () {
        $result = app(Redactor::class)->redact(['payload' => arrayOf(10)], 'boundary');

        expect($result['payload'])->not->toHaveKey('_large_object_redacted')
            ->and($result['payload'])->toHaveCount(10);
    });

    it('redacts an array one item over max_object_size', function () {
        $result = app(Redactor::class)->redact(['payload' => arrayOf(11)], 'boundary');

        expect($result['payload'])->toHaveKey('_large_object_redacted')
            ->and($result['payload']['_large_object_redacted'])->toContain('11 items');
    });

    it('reports the real item count in the marker', function () {
        $result = app(Redactor::class)->redact(['payload' => arrayOf(25)], 'boundary');

        expect($result['payload']['_large_object_redacted'])->toContain('25 items')
            ->and($result['payload']['_large_object_redacted'])->not->toContain('24 items')
            ->and($result['payload']['_large_object_redacted'])->not->toContain('26 items');
    });

    it('does nothing at all when redact_large_objects is off', function () {
        config()->set('redactor.profiles.boundary', boundaryProfile([
            'redact_large_objects' => false,
            'max_object_size' => 10,
        ]));

        expect(app(Redactor::class)->redact(['payload' => arrayOf(50)], 'boundary')['payload'])
            ->toHaveCount(50);
    });
});

describe('max_value_length boundary', function () {
    beforeEach(function () {
        config()->set('redactor.profiles.boundary', boundaryProfile(['max_value_length' => 20]));
    });

    it('leaves a string of exactly max_value_length alone', function () {
        $value = str_repeat('a', 20);

        expect(app(Redactor::class)->redact(['s' => $value], 'boundary'))->toBe(['s' => $value]);
    });

    it('redacts a string one character over max_value_length', function () {
        $result = app(Redactor::class)->redact(['s' => str_repeat('a', 21)], 'boundary');

        expect($result['s'])->toBe('[REDACTED] (String with 21 characters)');
    });

    it('reports the real length in the marker', function () {
        $result = app(Redactor::class)->redact(['s' => str_repeat('a', 500)], 'boundary');

        expect($result['s'])->toContain('500 characters')
            ->and($result['s'])->not->toContain('499 characters')
            ->and($result['s'])->not->toContain('501 characters');
    });

    it('marks the payload as redacted when the limit trips', function () {
        config()->set('redactor.profiles.boundary', boundaryProfile([
            'max_value_length' => 20,
            'mark_redacted' => true,
            'track_redacted_keys' => true,
        ]));

        $result = app(Redactor::class)->redactWithMetadata(['s' => str_repeat('a', 21)], 'boundary');

        expect($result->wasRedacted)->toBeTrue()
            ->and($result->redactedKeys)->toBe(['s']);
    });
});

describe('entropy threshold and length boundaries', function () {
    it('skips a token one character under min_length', function () {
        config()->set('redactor.profiles.boundary', boundaryProfile([
            'strategies' => [ShannonEntropyStrategy::class],
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 1.0,
                'min_length' => 16,
                'exclusion_patterns' => [],
            ],
        ]));

        $short = 'Zx7Qm4Kd9Rb2Vn6'; // 15 characters

        expect(strlen($short))->toBe(15)
            ->and(app(Redactor::class)->redact(['t' => $short], 'boundary'))->toBe(['t' => $short]);
    });

    it('inspects a token of exactly min_length', function () {
        config()->set('redactor.profiles.boundary', boundaryProfile([
            'strategies' => [ShannonEntropyStrategy::class],
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 1.0,
                'min_length' => 16,
                'exclusion_patterns' => [],
            ],
        ]));

        $exact = 'Zx7Qm4Kd9Rb2Vn6T'; // 16 characters

        expect(strlen($exact))->toBe(16)
            ->and(app(Redactor::class)->redact(['t' => $exact], 'boundary'))->toBe(['t' => '[REDACTED]']);
    });

    it('redacts at exactly the threshold, not only above it', function () {
        $token = 'abcdefgh'; // 8 distinct characters => exactly 3.0 bits
        $entropy = (new ShannonEntropyStrategy)->calculateShannonEntropy($token);

        expect($entropy)->toBe(3.0);

        config()->set('redactor.profiles.boundary', boundaryProfile([
            'strategies' => [ShannonEntropyStrategy::class],
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 3.0,
                'min_length' => 8,
                'exclusion_patterns' => [],
            ],
        ]));

        expect(app(Redactor::class)->redact(['t' => $token], 'boundary'))->toBe(['t' => '[REDACTED]']);
    });

    it('leaves a token just under the threshold alone', function () {
        $token = 'abcdefgh';

        config()->set('redactor.profiles.boundary', boundaryProfile([
            'strategies' => [ShannonEntropyStrategy::class],
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 3.01,
                'min_length' => 8,
                'exclusion_patterns' => [],
            ],
        ]));

        expect(app(Redactor::class)->redact(['t' => $token], 'boundary'))->toBe(['t' => $token]);
    });

    it('does nothing at all when entropy detection is disabled', function () {
        config()->set('redactor.profiles.boundary', boundaryProfile([
            'strategies' => [ShannonEntropyStrategy::class],
            'shannon_entropy' => [
                'enabled' => false,
                'threshold' => 0.1,
                'min_length' => 1,
                'exclusion_patterns' => [],
            ],
        ]));

        expect(app(Redactor::class)->redact(['t' => 'Zx7Qm4Kd9Rb2Vn6Tp1Ws8'], 'boundary'))
            ->toBe(['t' => 'Zx7Qm4Kd9Rb2Vn6Tp1Ws8']);
    });
});

describe('max_depth boundary', function () {
    it('walks exactly max_depth levels and replaces the next', function () {
        config()->set('redactor.profiles.boundary', boundaryProfile([
            'strategies' => [RegexPatternsStrategy::class],
            'patterns' => ['secret' => '/SECRET/'],
            'max_depth' => 3,
        ]));

        // Depth 1 = the root array, 2 = 'a', 3 = 'b', 4 = 'c' (over the limit).
        $result = app(Redactor::class)->redact(
            ['a' => ['b' => ['c' => ['leaf' => 'SECRET']]]],
            'boundary'
        );

        expect($result['a']['b']['c'])->toBe('[REDACTED] (Max depth of 3 exceeded)');
    });

    it('reaches a leaf sitting exactly at max_depth', function () {
        config()->set('redactor.profiles.boundary', boundaryProfile([
            'strategies' => [RegexPatternsStrategy::class],
            'patterns' => ['secret' => '/SECRET/'],
            'max_depth' => 3,
        ]));

        $result = app(Redactor::class)->redact(['a' => ['b' => ['leaf' => 'SECRET']]], 'boundary');

        expect($result['a']['b']['leaf'])->toBe('[REDACTED]');
    });
});

describe('partial mode keep boundary', function () {
    it('masks everything when the match is exactly keep characters', function () {
        $rule = new PatternRule(name: 't', pattern: '//', mode: PatternRule::MODE_PARTIAL, keep: 4);

        expect($rule->substitute('1234', '[R]'))->toBe('****');
    });

    it('reveals the tail as soon as the match is one character longer', function () {
        $rule = new PatternRule(name: 't', pattern: '//', mode: PatternRule::MODE_PARTIAL, keep: 4);

        expect($rule->substitute('12345', '[R]'))->toBe('*2345');
    });

    it('masks a match shorter than keep entirely', function () {
        $rule = new PatternRule(name: 't', pattern: '//', mode: PatternRule::MODE_PARTIAL, keep: 4);

        expect($rule->substitute('12', '[R]'))->toBe('**');
    });

    it('never returns an empty mask for an empty match', function () {
        $rule = new PatternRule(name: 't', pattern: '//', mode: PatternRule::MODE_PARTIAL, keep: 4);

        expect($rule->substitute('', '[R]'))->toBe('*');
    });
});

describe('Luhn length window boundaries', function () {
    it('rejects 11 digits and accepts a valid 12', function () {
        // 12 is the shortest real card length (Maestro); anything shorter is a
        // sequence number that happens to pass the checksum.
        expect(Validator::luhn('00000000000'))->toBeFalse()
            ->and(strlen('000000000000'))->toBe(12)
            ->and(Validator::luhn('000000000000'))->toBeTrue();
    });

    it('accepts 19 digits and rejects 20', function () {
        expect(Validator::luhn('0000000000000000000'))->toBeTrue()
            ->and(Validator::luhn('00000000000000000000'))->toBeFalse();
    });
});

describe('The entropy length gate is a shortcut, not a behaviour change', function () {
    function gatedProfile(int $minLength, float $threshold = 1.0): array
    {
        return boundaryProfile([
            'strategies' => [ShannonEntropyStrategy::class],
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => $threshold,
                'min_length' => $minLength,
                'exclusion_patterns' => [],
            ],
        ]);
    }

    it('still inspects a value of exactly min_length', function () {
        config()->set('redactor.profiles.boundary', gatedProfile(16));

        $exact = 'Zx7Qm4Kd9Rb2Vn6T'; // 16 characters

        expect(strlen($exact))->toBe(16)
            ->and(app(Redactor::class)->redact(['t' => $exact], 'boundary'))->toBe(['t' => '[REDACTED]']);
    });

    it('still finds a long token inside a long value', function () {
        config()->set('redactor.profiles.boundary', gatedProfile(20));

        $result = app(Redactor::class)->redact(
            ['t' => 'deploy used Zx7Qm4Kd9Rb2Vn6Tp1Ws8Yc3Hf then finished'],
            'boundary'
        );

        expect($result['t'])->toBe('deploy used [REDACTED] then finished');
    });

    it('skips a value that cannot contain a long enough token', function () {
        config()->set('redactor.profiles.boundary', gatedProfile(30));

        // Every token is short, and so is the value.
        expect(app(Redactor::class)->redact(['t' => 'a b c d e f'], 'boundary'))
            ->toBe(['t' => 'a b c d e f']);
    });

    it('counts characters, not bytes, once the byte gate passes', function () {
        // 10 characters but 30 bytes: the byte count lets it through, and the
        // character count must then reject it.
        config()->set('redactor.profiles.boundary', gatedProfile(20, 0.5));

        $multibyte = '日本語能力試験合格者'; // 10 chars, 30 bytes

        expect(strlen($multibyte))->toBe(30)
            ->and(mb_strlen($multibyte))->toBe(10)
            ->and(app(Redactor::class)->redact(['t' => $multibyte], 'boundary'))
            ->toBe(['t' => $multibyte]);
    });

    it('inspects a multibyte value that is genuinely long enough', function () {
        config()->set('redactor.profiles.boundary', gatedProfile(8, 2.0));

        $multibyte = '日本語能力試験合格'; // 9 characters

        expect(mb_strlen($multibyte))->toBe(9)
            ->and(app(Redactor::class)->redact(['t' => $multibyte], 'boundary'))
            ->toBe(['t' => '[REDACTED]']);
    });

    it('rejects a non-numeric min_length at config time', function () {
        config()->set('redactor.profiles.boundary', boundaryProfile([
            'strategies' => [ShannonEntropyStrategy::class],
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 1.0,
                'min_length' => 'lots',
                'exclusion_patterns' => [],
            ],
        ]));

        expect(fn () => RedactorConfig::fromConfig('boundary'))
            ->toThrow(\InvalidArgumentException::class, 'shannon_entropy.min_length');
    });

    it('analyses everything when a hand-built config carries no usable min_length', function () {
        // The gate is defensive as well as fast: a config assembled directly,
        // bypassing validation, must fall through to analysis rather than
        // silently skipping every value.
        $strategy = new class extends ShannonEntropyStrategy
        {
            public function isTooShort(string $s, array $cfg): bool
            {
                return $this->tooShort($s, $cfg);
            }
        };

        expect($strategy->isTooShort('short', ['min_length' => 'lots']))->toBeFalse()
            ->and($strategy->isTooShort('short', []))->toBeTrue()
            ->and($strategy->isTooShort(str_repeat('a', 40), []))->toBeFalse();
    });
});
