<?php

declare(strict_types=1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use Kirschbaum\Redactor\Detection\Confidence;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;

function confidenceProfile(array $patterns, array $overrides = []): array
{
    return array_merge([
        'enabled' => true,
        'strategies' => [RegexPatternsStrategy::class],
        'safe_keys' => [],
        'blocked_keys' => [],
        'patterns' => $patterns,
        'paths' => [],
        'operators' => ['default' => 'redact'],
        'min_confidence' => 0.0,
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

describe('Confidence arithmetic', function () {
    it('never exceeds certainty however many signals stack', function () {
        $confidence = Confidence::of(0.6);

        for ($i = 0; $i < 50; $i++) {
            $confidence = $confidence->with("s{$i}", 0.5, 'another signal');
        }

        expect($confidence->score)->toBeLessThanOrEqual(1.0)
            ->and($confidence->score)->toBeGreaterThan(0.99);
    });

    it('applies a positive signal to the remaining headroom, not flat', function () {
        // Flat addition would let two 0.6 signals claim 1.2 certainty, and
        // would let one strong signal swamp everything after it.
        $once = Confidence::of(0.5)->with('a', 0.5, 'r');
        $twice = $once->with('b', 0.5, 'r');

        expect($once->score)->toBe(0.75)
            ->and($twice->score)->toBe(0.875);
    });

    it('reduces the score for a negative signal', function () {
        expect(Confidence::of(0.8)->with('a', -0.5, 'r')->score)
            ->toBeLessThan(0.8);
    });

    it('clamps a base outside the range', function () {
        expect(Confidence::of(5.0)->score)->toBe(1.0)
            ->and(Confidence::of(-5.0)->score)->toBe(0.0);
    });

    it('explains every contribution', function () {
        $confidence = Confidence::of(0.6, 'pattern matched')->with('luhn', 0.75, 'checksum passed');

        expect($confidence->explain())->toHaveCount(2)
            ->and($confidence->explain()[1])->toContain('luhn')
            ->and($confidence->explain()[1])->toContain('checksum passed');
    });

    it('labels bands a human can sort by', function () {
        expect(Confidence::of(0.95)->label())->toBe('high')
            ->and(Confidence::of(0.7)->label())->toBe('medium')
            ->and(Confidence::of(0.4)->label())->toBe('low')
            ->and(Confidence::of(0.1)->label())->toBe('very-low');
    });
});

describe('Scoring a detection', function () {
    it('raises the score when a checksum passes', function () {
        config()->set('redactor.profiles.conf', confidenceProfile([
            'card' => ['pattern' => '/\b\d{16}\b/', 'confidence' => 0.3, 'validator' => 'luhn'],
        ], ['track_redacted_keys' => true, 'mark_redacted' => true]));

        $result = app(Redactor::class)->redactWithMetadata(['v' => '4111111111111111'], 'conf');

        expect($result->findings[0]->confidence?->score)->toBeGreaterThan(0.3)
            ->and(implode(' ', $result->findings[0]->confidence?->explain() ?? []))->toContain('luhn');
    });

    it('raises the score when a credential keyword sits beside the match', function () {
        config()->set('redactor.profiles.conf', confidenceProfile([
            'token' => ['pattern' => '/[a-z0-9]{20,}/', 'confidence' => 0.3],
        ]));

        $bare = app(Redactor::class)->redactWithMetadata(['v' => 'abcdefghijklmnopqrstuvwxyz'], 'conf');
        $labelled = app(Redactor::class)->redactWithMetadata(['v' => 'token=abcdefghijklmnopqrstuvwxyz'], 'conf');

        expect($labelled->findings[0]->confidence?->score)
            ->toBeGreaterThan($bare->findings[0]->confidence?->score ?? 1.0);
    });

    it('raises the score when the key itself names a credential', function () {
        config()->set('redactor.profiles.conf', confidenceProfile([
            'token' => ['pattern' => '/[a-z0-9]{20,}/', 'confidence' => 0.3],
        ]));

        $neutral = app(Redactor::class)->redactWithMetadata(['note' => 'abcdefghijklmnopqrstuvwxyz'], 'conf');
        $named = app(Redactor::class)->redactWithMetadata(['api_key' => 'abcdefghijklmnopqrstuvwxyz'], 'conf');

        expect($named->findings[0]->confidence?->score)
            ->toBeGreaterThan($neutral->findings[0]->confidence?->score ?? 1.0);
    });

    it('ignores a keyword that only appears after the match', function () {
        // "<value> token" is usually the next field, not a label for this one.
        config()->set('redactor.profiles.conf', confidenceProfile([
            'token' => ['pattern' => '/^[a-z0-9]{20,}/', 'confidence' => 0.3],
        ]));

        $after = app(Redactor::class)->redactWithMetadata(['v' => 'abcdefghijklmnopqrstuvwxyz token'], 'conf');

        expect($after->findings[0]->confidence?->score)->toBe(0.3);
    });
});

describe('The confidence floor', function () {
    it('leaves a detection below the floor completely alone', function () {
        config()->set('redactor.profiles.conf', confidenceProfile([
            'weak' => ['pattern' => '/\bmaybe-\w+/', 'confidence' => 0.2],
        ], ['min_confidence' => 0.5]));

        expect(app(Redactor::class)->redact(['v' => 'maybe-secret'], 'conf'))
            ->toBe(['v' => 'maybe-secret']);
    });

    it('acts on the same detection once the floor drops', function () {
        config()->set('redactor.profiles.conf', confidenceProfile([
            'weak' => ['pattern' => '/\bmaybe-\w+/', 'confidence' => 0.2],
        ], ['min_confidence' => 0.1]));

        expect(app(Redactor::class)->redact(['v' => 'maybe-secret'], 'conf'))
            ->toBe(['v' => '[REDACTED]']);
    });

    it('does not report a filtered detection as a redaction', function () {
        config()->set('redactor.profiles.conf', confidenceProfile([
            'weak' => ['pattern' => '/\bmaybe-\w+/', 'confidence' => 0.2],
        ], ['min_confidence' => 0.5]));

        expect(app(Redactor::class)->redactWithMetadata(['v' => 'maybe-secret'], 'conf')->wasRedacted)
            ->toBeFalse();
    });

    it('lets a weak rule survive the floor when context corroborates it', function () {
        // The whole point of scoring: the same pattern is noise on its own and
        // a finding next to a keyword, without editing the pattern.
        config()->set('redactor.profiles.conf', confidenceProfile([
            'weak' => ['pattern' => '/[a-z0-9]{20,}/', 'confidence' => 0.3],
        ], ['min_confidence' => 0.45]));

        expect(app(Redactor::class)->redact(['note' => 'abcdefghijklmnopqrstuvwxyz'], 'conf'))
            ->toBe(['note' => 'abcdefghijklmnopqrstuvwxyz']);

        expect(app(Redactor::class)->redact(['note' => 'secret=abcdefghijklmnopqrstuvwxyz'], 'conf'))
            ->toBe(['note' => 'secret=[REDACTED]']);
    });

    it('rejects a floor outside 0 to 1', function () {
        config()->set('redactor.profiles.conf', confidenceProfile([], ['min_confidence' => 1.5]));

        expect(fn () => RedactorConfig::fromConfig('conf'))
            ->toThrow(\InvalidArgumentException::class, 'min_confidence');
    });
});

describe('Confidence in scan output', function () {
    beforeEach(function () {
        config(['redactor.scan.profile' => 'file_scan', 'redactor.scan.baseline' => null]);

        $this->dir = sys_get_temp_dir().'/redactor_conf_'.uniqid();
        mkdir($this->dir);
        file_put_contents($this->dir.'/app.env', "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\ncard 4111111111111111\n");
    });

    afterEach(fn () => cleanupDirectory($this->dir));

    it('reports a score, a severity and the signals behind it', function () {
        Artisan::call('redactor:scan', ['paths' => [$this->dir], '--output' => 'json']);

        $finding = json_decode(Artisan::output(), true)[0]['findings'][0];

        expect($finding)->toHaveKeys(['entity', 'confidence', 'severity', 'signals'])
            ->and($finding['confidence'])->toBeFloat()
            ->and($finding['severity'])->toBeIn(['high', 'medium', 'low', 'very-low'])
            ->and($finding['signals'])->not->toBeEmpty();
    });

    it('maps severity onto SARIF levels', function () {
        Artisan::call('redactor:scan', ['paths' => [$this->dir], '--output' => 'sarif']);

        $results = json_decode(Artisan::output(), true)['runs'][0]['results'];

        foreach ($results as $result) {
            expect($result['level'])->toBeIn(['error', 'warning', 'note'])
                ->and($result['properties'])->toHaveKey('confidence');
        }
    });

    it('filters by --min-confidence', function () {
        Artisan::call('redactor:scan', ['paths' => [$this->dir], '--output' => 'json']);
        $all = count(json_decode(Artisan::output(), true)[0]['findings']);

        Artisan::call('redactor:scan', ['paths' => [$this->dir], '--output' => 'json', '--min-confidence' => '0.99']);
        $strict = count(json_decode(Artisan::output(), true)[0]['findings'] ?? []);

        expect($all)->toBeGreaterThan(0)
            ->and($strict)->toBeLessThanOrEqual($all);
    });

    it('rejects a --min-confidence outside 0 to 1', function () {
        $exit = Artisan::call('redactor:scan', ['paths' => [$this->dir], '--min-confidence' => '7']);

        expect($exit)->toBe(1)
            ->and(Artisan::output())->toContain('between 0 and 1');
    });

    it('shows a severity column in the table', function () {
        Artisan::call('redactor:scan', ['paths' => [$this->dir]]);

        expect(Artisan::output())->toContain('Severity');
    });
});
