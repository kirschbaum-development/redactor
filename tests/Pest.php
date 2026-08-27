<?php

use Tests\TestCase;

/*
|--------------------------------------------------------------------------
| Test Case
|--------------------------------------------------------------------------
|
| The closure you provide to your test functions is always bound to a specific PHPUnit test
| case class. By default, that class is "PHPUnit\Framework\TestCase". Of course, you may
| need to change it using the "pest()" function to bind a different classes or traits.
|
*/

pest()->extend(TestCase::class)
 // ->use(Illuminate\Foundation\Testing\RefreshDatabase::class)
    ->in('Feature', 'Unit', 'Performance');

/*
|--------------------------------------------------------------------------
| Expectations
|--------------------------------------------------------------------------
|
| When you're writing tests, you often need to check that values meet certain conditions. The
| "expect()" function gives you access to a set of "expectations" methods that you can use
| to assert different things. Of course, you may extend the Expectation API at any time.
|
*/

expect()->extend('toBeOne', function () {
    return $this->toBe(1);
});

/*
|--------------------------------------------------------------------------
| Functions
|--------------------------------------------------------------------------
|
| While Pest is very powerful out-of-the-box, you may have some testing code specific to your
| project that you don't want to repeat in every file. Here you can also expose helpers as
| global functions to help you to reduce the number of lines of code in your test files.
|
*/

/**
 * Whether a coverage driver is actively instrumenting this run.
 *
 * Instrumentation dominates the clock and flattens the difference between a
 * fast and a slow implementation, so timing assertions made under it are
 * meaningless - a benchmark that shows 8x uninstrumented showed 1.4x under
 * pcov in CI. Timing-sensitive tests skip themselves rather than flake.
 */
function runningWithCoverage(): bool
{
    if (extension_loaded('pcov') && (bool) ini_get('pcov.enabled')) {
        return true;
    }

    return extension_loaded('xdebug')
        && str_contains((string) ini_get('xdebug.mode'), 'coverage');
}

/**
 * Clean up directory recursively
 */
function cleanupDirectory(string $dir): void
{
    if (! is_dir($dir)) {
        return;
    }

    $files = scandir($dir);
    foreach ($files as $file) {
        if ($file === '.' || $file === '..') {
            continue;
        }

        $path = $dir.'/'.$file;

        if (is_dir($path)) {
            cleanupDirectory($path);
        } else {
            // Ensure file is writable before deletion
            chmod($path, 0644);
            unlink($path);
        }
    }

    rmdir($dir);
}
