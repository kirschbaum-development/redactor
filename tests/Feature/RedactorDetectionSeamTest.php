<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Detection\Confidence;
use Kirschbaum\Redactor\Detection\Detection;
use Kirschbaum\Redactor\Detection\DetectionSet;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Scanner\Scanner;
use Kirschbaum\Redactor\Strategies\BlockedKeysStrategy;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;
use Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy;

const SEAM_EMAIL = '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/';

function seamProfile(array $overrides = []): array
{
    return array_merge([
        'enabled' => true,
        'strategies' => [BlockedKeysStrategy::class, RegexPatternsStrategy::class, ShannonEntropyStrategy::class],
        'safe_keys' => [],
        'blocked_keys' => [],
        'patterns' => [
            'stripe' => ['pattern' => '/sk_live_[A-Za-z0-9]{24}/', 'entity' => 'stripe_key', 'confidence' => 0.95],
            'email' => ['pattern' => SEAM_EMAIL, 'entity' => 'email'],
        ],
        'operators' => ['default' => 'redact'],
        'min_confidence' => 0.0,
        'replacement' => '[REDACTED]',
        'mark_redacted' => false,
        'track_redacted_keys' => false,
        'non_redactable_object_behavior' => 'preserve',
        'max_value_length' => null,
        'redact_large_objects' => false,
        'max_object_size' => 100,
        'pseudonymization' => ['key' => testPseudonymizationKey()],
        'shannon_entropy' => [
            'enabled' => true,
            'threshold' => 4.0,
            'min_length' => 20,
            'exclusion_patterns' => [],
        ],
    ], $overrides);
}

function seamDetection(string $rule, int $offset, string $value, float $score = 0.6): Detection
{
    return new Detection(entity: $rule, rule: $rule, offset: $offset, value: $value, confidence: Confidence::of($score));
}

describe('Surrogates survive the rest of the chain', function () {
    it('does not let the entropy detector eat a surrogate the regex detector just wrote', function () {
        config()->set('redactor.profiles.seam', seamProfile([
            'operators' => ['default' => 'redact', 'stripe_key' => ['surrogate' => ['preserve_prefix' => 8]]],
        ]));

        $result = app(Redactor::class)->redact('key sk_live_4eC39HqLyjWDarjtT1zdp7dc end', 'seam');

        expect($result)->toMatch('/^key sk_live_[A-Za-z0-9]{24} end$/')
            ->and($result)->not->toContain('4eC39HqLyjWDarjtT1zdp7dc')
            ->and($result)->not->toContain('[REDACTED]');
    });

    it('reports the original secret, never the surrogate, in the findings', function () {
        config()->set('redactor.profiles.seam', seamProfile([
            'operators' => ['default' => 'redact', 'stripe_key' => 'surrogate'],
        ]));

        $result = app(Redactor::class)->redactWithMetadata('key sk_live_4eC39HqLyjWDarjtT1zdp7dc end', 'seam');

        expect($result->findings)->toHaveCount(1)
            ->and($result->findings[0]->rule)->toBe('stripe')
            ->and($result->findings[0]->matched)->toBe('sk_live_4eC39HqLyjWDarjtT1zdp7dc');
    });
});

describe('Offsets are always against the original value', function () {
    it('keeps a later rule\'s offsets correct after an earlier rule changed the length', function () {
        config()->set('redactor.profiles.seam', seamProfile([
            'patterns' => [
                'email' => SEAM_EMAIL,
                'card' => ['pattern' => '/\b\d{16}\b/', 'validator' => 'luhn'],
            ],
            'shannon_entropy' => ['enabled' => false],
        ]));

        $line = 'contact a@b.com card 4111111111111111 end';
        $result = app(Redactor::class)->redactWithMetadata($line, 'seam');

        $byRule = [];
        foreach ($result->findings as $finding) {
            $byRule[$finding->rule] = $finding->offset;
        }

        expect($byRule['email'])->toBe(strpos($line, 'a@b.com'))
            ->and($byRule['card'])->toBe(strpos($line, '4111'))
            ->and($result->value)->toBe('contact [REDACTED] card [REDACTED] end');
    });

    it('gives the scanner the right column for the second finding on a line', function () {
        $path = tempnam(sys_get_temp_dir(), 'seam');
        $line = 'contact a@b.com card 4111111111111111 end';
        file_put_contents($path, $line."\n");

        try {
            $findings = app(Scanner::class)->scanFile($path, 'file_scan')->findings;
        } finally {
            unlink($path);
        }

        $columns = [];
        foreach ($findings as $finding) {
            $columns[$finding->rule] = $finding->column;
        }

        expect($columns['email'])->toBe(strpos($line, 'a@b.com') + 1)
            ->and($columns['credit_card'])->toBe(strpos($line, '4111') + 1);
    });
});

describe('Entropy detections are first-class', function () {
    it('carries a score and its signals', function () {
        config()->set('redactor.profiles.seam', seamProfile(['patterns' => []]));

        $result = app(Redactor::class)->redactWithMetadata(['v' => 'Zx7Qm4Kd9Rb2Vn6Tp1Ws8Yc3Hf'], 'seam');

        expect($result->findings[0]->rule)->toBe('shannon_entropy')
            ->and($result->findings[0]->entity)->toBe('high_entropy')
            ->and($result->findings[0]->confidence?->score)->toBeGreaterThanOrEqual(0.5)
            ->and(implode(' ', $result->findings[0]->confidence?->explain() ?? []))->toContain('entropy');
    });

    it('scores higher beside a credential keyword', function () {
        config()->set('redactor.profiles.seam', seamProfile(['patterns' => []]));

        $bare = app(Redactor::class)->redactWithMetadata(['v' => 'Zx7Qm4Kd9Rb2Vn6Tp1Ws8Yc3Hf'], 'seam');
        $labelled = app(Redactor::class)->redactWithMetadata(['v' => 'token=Zx7Qm4Kd9Rb2Vn6Tp1Ws8Yc3Hf'], 'seam');

        expect($labelled->findings[0]->confidence?->score)
            ->toBeGreaterThan($bare->findings[0]->confidence?->score ?? 1.0);
    });

    it('respects the confidence floor', function () {
        config()->set('redactor.profiles.seam', seamProfile(['patterns' => [], 'min_confidence' => 0.99]));

        $result = app(Redactor::class)->redactWithMetadata(['v' => 'Zx7Qm4Kd9Rb2Vn6Tp1Ws8Yc3Hf'], 'seam');

        expect($result->wasRedacted)->toBeFalse()
            ->and($result->value)->toBe(['v' => 'Zx7Qm4Kd9Rb2Vn6Tp1Ws8Yc3Hf']);
    });

    it('goes through the configured operator', function () {
        config()->set('redactor.profiles.seam', seamProfile([
            'patterns' => [],
            'operators' => ['default' => 'hash'],
        ]));

        $result = app(Redactor::class)->redact(['v' => 'note Zx7Qm4Kd9Rb2Vn6Tp1Ws8Yc3Hf end'], 'seam');

        expect($result['v'])->toMatch('/^note \[high_entropy:[a-z0-9]+\] end$/');
    });

    it('still fails closed when the tokeniser cannot split the value', function () {
        config()->set('redactor.profiles.seam', seamProfile([
            'patterns' => [],
            'operators' => ['default' => 'hash'],
        ]));

        $result = app(Redactor::class)->redact(['v' => "\xff\xfe bad Zx7Qm4Kd9Rb2Vn6Tp1Ws8Yc3Hf"], 'seam');

        // Plain replacement, whatever the operator policy says: there is
        // nothing meaningful to hash.
        expect($result['v'])->toBe('[REDACTED]');
    });
});

describe('Overlap resolution', function () {
    it('lets a validated card beat the digit run that also matched it', function () {
        config()->set('redactor.profiles.seam', seamProfile([
            'patterns' => [
                'digits' => ['pattern' => '/\d+/', 'entity' => 'digits'],
                'card' => ['pattern' => '/\b\d{16}\b/', 'validator' => 'luhn', 'entity' => 'credit_card'],
            ],
            'operators' => ['default' => 'redact', 'credit_card' => ['partial' => ['keep' => 4]]],
            'shannon_entropy' => ['enabled' => false],
        ]));

        expect(app(Redactor::class)->redact('paid 4111111111111111 ok', 'seam'))
            ->toBe('paid ************1111 ok');
    });

    it('lets the rule listed first win an equal-score overlap', function () {
        config()->set('redactor.profiles.seam', seamProfile([
            'patterns' => [
                'url_with_auth' => ['pattern' => '/(https?:\/\/[^:\/\s]+:)([^@\/\s]+)(@)/', 'capture' => 2],
                'email' => SEAM_EMAIL,
            ],
            'shannon_entropy' => ['enabled' => false],
        ]));

        expect(app(Redactor::class)->redact('https://admin:hunter2@db.example.com/x', 'seam'))
            ->toBe('https://admin:[REDACTED]@db.example.com/x');
    });

    it('never returns overlapping spans', function () {
        $kept = DetectionSet::resolve([
            seamDetection('a', 0, 'aaaaa', 0.6),
            seamDetection('b', 3, 'bbbbb', 0.7),
            seamDetection('c', 6, 'ccccc', 0.65),
            seamDetection('d', 20, 'dd', 0.2),
        ], 0.3);

        expect(array_map(fn (Detection $d) => $d->rule, $kept))->toBe(['b']);
    });

    it('keeps the order of arrival as the tie-break, not the order of offset', function () {
        $kept = DetectionSet::resolve([
            seamDetection('later', 2, 'xxxx'),
            seamDetection('earlier', 0, 'yyyy'),
        ]);

        expect(array_map(fn (Detection $d) => $d->rule, $kept))->toBe(['later']);
    });

    it('lets a fail-closed detection swallow everything', function () {
        $kept = DetectionSet::resolve([
            seamDetection('a', 0, 'aaaaa', 0.9),
            Detection::failClosed('x', 'x', 'aaaaa bbbbb', '', 'engine gave up'),
        ], 0.95);

        expect($kept)->toHaveCount(1)
            ->and($kept[0]->failClosed)->toBeTrue();
    });
});

describe('Preserved detections are reported, not redacted', function () {
    it('lists the finding without marking the payload redacted', function () {
        config()->set('redactor.profiles.seam', seamProfile([
            'operators' => ['default' => 'redact', 'email' => 'preserve'],
            'shannon_entropy' => ['enabled' => false],
        ]));

        $result = app(Redactor::class)->redactWithMetadata(['v' => 'hi bob@example.com'], 'seam');

        expect($result->value)->toBe(['v' => 'hi bob@example.com'])
            ->and($result->wasRedacted)->toBeFalse()
            ->and($result->findings)->toHaveCount(1)
            ->and($result->findings[0]->rule)->toBe('email');
    });
});

describe('Keyword prefilter', function () {
    it('skips a rule when none of its keywords appear in the subject', function () {
        config()->set('redactor.profiles.seam', seamProfile([
            'patterns' => [
                'phone_bare' => ['pattern' => '/\b\d{10}\b/', 'keywords' => ['phone', 'tel']],
            ],
            'shannon_entropy' => ['enabled' => false],
        ]));

        expect(app(Redactor::class)->redact('started at 1694600000', 'seam'))
            ->toBe('started at 1694600000')
            ->and(app(Redactor::class)->redact('Phone: 5558675309', 'seam'))
            ->toBe('Phone: [REDACTED]');
    });

    it('matches keywords case-insensitively', function () {
        config()->set('redactor.profiles.seam', seamProfile([
            'patterns' => [
                'email' => ['pattern' => SEAM_EMAIL, 'keywords' => ['@']],
            ],
            'shannon_entropy' => ['enabled' => false],
        ]));

        expect(app(Redactor::class)->redact('BOB@EXAMPLE.COM', 'seam'))->toBe('[REDACTED]');
    });

    it('rejects a non-list keywords option', function () {
        config()->set('redactor.profiles.seam', seamProfile([
            'patterns' => ['x' => ['pattern' => '/x/', 'keywords' => 'phone']],
        ]));

        app(Redactor::class)->redact('x', 'seam');
    })->throws(\InvalidArgumentException::class, 'keywords');
});
