<?php

declare(strict_types=1);

use Kirschbaum\Redactor\Redactor;

/**
 * Performance guards.
 *
 * Wall-clock thresholds are useless on a shared CI runner, so every assertion
 * here is relative: either one implementation against another in the same
 * process, or work against a calibration loop measured moments earlier. What
 * they catch is a change in complexity, which is the regression that matters.
 */
function logPayload(): array
{
    return [
        'level' => 'info',
        'event' => 'request.handled',
        'trace_id' => 'abc123',
        'user' => ['id' => 42, 'email' => 'a@b.com', 'name' => 'Bob', 'password' => 'x'],
        'request' => [
            'method' => 'GET',
            'path' => '/orders/42',
            'headers' => ['authorization' => 'Bearer zzz', 'user_agent' => 'Mozilla/5.0'],
        ],
        'meta' => array_fill_keys(array_map(fn (int $i) => "field_{$i}", range(1, 20)), 'value-string-here'),
    ];
}

/** Nanoseconds for one redaction of the standard payload. */
function timeRedaction(string $profile, int $iterations = 500): float
{
    $redactor = app(Redactor::class);
    $payload = logPayload();

    $redactor->redact($payload, $profile); // warm the strategy cache

    $start = hrtime(true);
    for ($i = 0; $i < $iterations; $i++) {
        $redactor->redact($payload, $profile);
    }

    return (hrtime(true) - $start) / $iterations;
}

/** Nanoseconds for a trivial loop iteration, to normalise for machine speed. */
function calibration(int $iterations = 500_000): float
{
    $sink = 0;

    $start = hrtime(true);
    for ($i = 0; $i < $iterations; $i++) {
        $sink += $i % 7;
    }

    return (hrtime(true) - $start) / $iterations;
}

describe('Redaction throughput', function () {
    it('redacts a realistic log context within budget for its machine', function () {
        $unit = calibration();
        $perRedaction = timeRedaction('default');

        // Measured at roughly 5,000 calibration units on PHP 8.5. The ceiling
        // is set well above that so an ordinary runner never fails, while a
        // change that makes redaction quadratic still does.
        expect($perRedaction / $unit)->toBeLessThan(50_000.0);
    });

    it('keeps the performance profile faster than the default', function () {
        // The performance profile exists to skip work. If it stops being
        // faster, it has stopped doing its job.
        expect(timeRedaction('performance'))->toBeLessThan(timeRedaction('default'));
    });

    it('keeps the default profile faster than strict', function () {
        expect(timeRedaction('default'))->toBeLessThan(timeRedaction('strict'));
    });
});

describe('Redaction scaling', function () {
    it('scales linearly with payload size, not quadratically', function () {
        $redactor = app(Redactor::class);

        $build = fn (int $n) => array_fill_keys(
            array_map(fn (int $i) => "field_{$i}", range(1, $n)),
            'some ordinary value'
        );

        $small = $build(2_000);
        $large = $build(20_000);

        config()->set('redactor.profiles.scaling', array_merge(
            config('redactor.profiles.default'),
            ['redact_large_objects' => false, 'mark_redacted' => false]
        ));

        $redactor->redact($small, 'scaling');

        $start = hrtime(true);
        $redactor->redact($small, 'scaling');
        $smallTime = hrtime(true) - $start;

        $start = hrtime(true);
        $redactor->redact($large, 'scaling');
        $largeTime = hrtime(true) - $start;

        // 10x the input should cost roughly 10x. Quadratic behaviour would be
        // 100x; the ceiling of 30x absorbs GC and cache noise.
        expect($largeTime / max($smallTime, 1))->toBeLessThan(30.0);
    });

    it('holds memory flat for a large payload', function () {
        config()->set('redactor.profiles.scaling', array_merge(
            config('redactor.profiles.default'),
            ['redact_large_objects' => false, 'mark_redacted' => false]
        ));

        $payload = array_fill_keys(
            array_map(fn (int $i) => "field_{$i}", range(1, 50_000)),
            'value with some text in it'
        );

        $before = memory_get_usage();
        app(Redactor::class)->redact($payload, 'scaling');
        $growthMb = (memory_get_usage() - $before) / 1_048_576;

        // The redacted copy is the only allocation that should scale with the
        // input; anything holding per-node state would blow past this.
        expect($growthMb)->toBeLessThan(64.0);
    });

    it('does not let the entropy cache grow without bound across calls', function () {
        // The cache lives on RedactionContext, which is per-redaction. A cache
        // that outlived a call would grow forever in a long-running worker.
        config()->set('redactor.profiles.scaling', array_merge(
            config('redactor.profiles.default'),
            ['mark_redacted' => false]
        ));

        $redactor = app(Redactor::class);

        for ($i = 0; $i < 200; $i++) {
            $redactor->redact(['note' => "unique-string-number-{$i}-with-padding"], 'scaling');
        }

        $before = memory_get_usage();

        for ($i = 0; $i < 2_000; $i++) {
            $redactor->redact(['note' => "another-unique-string-{$i}-with-padding"], 'scaling');
        }

        expect((memory_get_usage() - $before) / 1_048_576)->toBeLessThan(4.0);
    });
});
