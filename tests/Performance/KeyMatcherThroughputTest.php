<?php

declare(strict_types=1);

use Kirschbaum\Redactor\Support\KeyMatcher;

describe('KeyMatcher throughput', function () {
    afterEach(fn () => KeyMatcher::flush());

    it('is markedly faster than rebuilding a regex per key', function () {
        $patterns = ['password', '*token*', '*key*', '*secret*', 'authorization', 'user_*_data'];
        $keys = ['user_id', 'created_at', 'api_token', 'normal_field', 'trace_id', 'status'];

        $matcher = KeyMatcher::for($patterns);
        $iterations = 20_000;

        $start = hrtime(true);
        for ($i = 0; $i < $iterations; $i++) {
            foreach ($keys as $key) {
                $matcher->matches($key);
            }
        }
        $compiled = hrtime(true) - $start;

        // The previous implementation, verbatim, so the regression this guards
        // against is the actual one.
        $start = hrtime(true);
        for ($i = 0; $i < $iterations; $i++) {
            foreach ($keys as $key) {
                $keyLower = strtolower($key);
                foreach ($patterns as $pattern) {
                    if (! str_contains($pattern, '*')) {
                        if ($keyLower === strtolower($pattern)) {
                            break;
                        }

                        continue;
                    }
                    $regex = '/^'.str_replace('\*', '.*', preg_quote($pattern, '/')).'$/i';
                    if (preg_match($regex, $keyLower) === 1) {
                        break;
                    }
                }
            }
        }
        $rebuilt = hrtime(true) - $start;

        // Measured at roughly 8x uninstrumented; asserting 2x leaves generous
        // room for a loaded runner while still failing on a real regression.
        expect($compiled)->toBeLessThan($rebuilt / 2);
    });
})->skip(runningWithCoverage(), 'Timings are meaningless under coverage instrumentation.');
