<?php

declare(strict_types=1);

use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy;
use Kirschbaum\Redactor\Support\KeyMatcher;

/**
 * Guards for the shortcuts on the hot path.
 *
 * Each of these was worth between 1.2x and 40x when it was added, and each is
 * the kind of thing a later refactor removes without noticing - a lookup moved
 * back inside a loop, a gate dropped while rearranging a condition. The
 * assertions are relative and structural rather than wall-clock, so they say
 * something true on any machine.
 */
function fastest(callable $f, int $iterations): float
{
    $f();
    $best = PHP_FLOAT_MAX;

    for ($round = 0; $round < 3; $round++) {
        $start = hrtime(true);
        for ($i = 0; $i < $iterations; $i++) {
            $f();
        }
        $best = min($best, (hrtime(true) - $start) / $iterations);
    }

    return $best;
}

describe('Compiled key matchers stay compiled', function () {
    it('resolves one matcher per profile, not one per call', function () {
        $first = RedactorConfig::fromConfig('default');
        $second = RedactorConfig::fromConfig('default');

        // Structural, so it holds regardless of machine speed: the same
        // profile must hand back the same compiled matcher.
        expect($first->safeKeyMatcher)->toBe($second->safeKeyMatcher)
            ->and($first->blockedKeyMatcher)->toBe($second->blockedKeyMatcher);
    });

    it('is far cheaper than looking the matcher up per call', function () {
        $config = RedactorConfig::fromConfig('default');
        $keys = ['user_id', 'password', 'created_at', 'normal_field', 'api_token'];

        $held = fastest(function () use ($config, $keys) {
            foreach ($keys as $key) {
                $config->blockedKeyMatcher->matches($key);
            }
        }, 20_000);

        // What it used to do: find the memoised matcher by rebuilding an
        // implode() of every configured key, on every single check.
        $lookedUp = fastest(function () use ($config, $keys) {
            foreach ($keys as $key) {
                KeyMatcher::for($config->blockedKeys)->matches($key);
            }
        }, 20_000);

        expect($held)->toBeLessThan($lookedUp / 2);
    })->skip(runningWithCoverage(), 'Timings are meaningless under coverage instrumentation.');
});

describe('Entropy skips what it cannot match', function () {
    it('is far cheaper for values below min_length', function () {
        $config = RedactorConfig::fromConfig('default');
        $context = new RedactionContext($config);
        $strategy = new ShannonEntropyStrategy;

        $short = ['info', 'GET', '/orders/42', 'Bob', 'pending', 'v2.14.1'];
        $long = [str_repeat('Zx7Qm4Kd9Rb2Vn6Tp1Ws8Yc3Hf ', 1)];

        $shortCost = fastest(function () use ($strategy, $short, $context) {
            foreach ($short as $v) {
                $strategy->shouldHandle($v, 'k', $context);
            }
        }, 20_000);

        $longCost = fastest(function () use ($strategy, $long, $context) {
            foreach ($long as $v) {
                $strategy->shouldHandle($v, 'k', $context);
            }
        }, 20_000);

        // Six short values must cost less than one value that clears the gate.
        expect($shortCost)->toBeLessThan($longCost);
    })->skip(runningWithCoverage(), 'Timings are meaningless under coverage instrumentation.');
});

describe('An unchanged payload is not rebuilt', function () {
    it('costs less to redact a clean payload than a matching one', function () {
        $redactor = app(Redactor::class);

        // Same shape, same size: the only difference is whether anything
        // matches, so the gap is the copy that no longer happens.
        $clean = ['a' => ['x' => 'plain'], 'b' => ['y' => 'plain'], 'c' => ['z' => 'plain']];
        $dirty = ['a' => ['x' => 'a@b.com'], 'b' => ['y' => 'plain'], 'c' => ['z' => 'plain']];

        $cleanCost = fastest(fn () => $redactor->redact($clean, 'default'), 10_000);
        $dirtyCost = fastest(fn () => $redactor->redact($dirty, 'default'), 10_000);

        expect($cleanCost)->toBeLessThan($dirtyCost);
    })->skip(runningWithCoverage(), 'Timings are meaningless under coverage instrumentation.');

    it('hands back the very same array when nothing matched', function () {
        $payload = ['a' => ['x' => 'plain'], 'b' => 'also plain'];

        $result = app(Redactor::class)->redact($payload, 'default');

        expect($result)->toBe($payload);
    });
});
