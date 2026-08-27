<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Strategies\BlockedKeysStrategy;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;
use Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy;
use Kirschbaum\Redactor\Support\Pcre;

/**
 * A pattern that is valid (so it survives config validation) but blows the
 * backtrack limit on a long subject. This is how a real PCRE failure reaches
 * the strategies: preg_match() returns false, which a boolean check reads as
 * "no match", and the secret ships.
 */
function catastrophicPattern(): string
{
    return '/^(a+)+b$/';
}

function catastrophicSubject(): string
{
    return str_repeat('a', 5000).'c';
}

describe('PCRE failures fail closed', function () {
    afterEach(function () {
        ini_restore('pcre.backtrack_limit');
    });

    it('sanity check: the probe pattern really does fail on this subject', function () {
        ini_set('pcre.backtrack_limit', '1000');

        $raw = @preg_match(catastrophicPattern(), catastrophicSubject());

        expect($raw)->toBeFalse()
            ->and(preg_last_error())->not->toBe(PREG_NO_ERROR);
    });

    it('treats an unevaluatable detection pattern as a match', function () {
        ini_set('pcre.backtrack_limit', '1000');

        config()->set('redactor.profiles.pcre', [
            'enabled' => true,
            'strategies' => [RegexPatternsStrategy::class],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => ['catastrophic' => catastrophicPattern()],
            'replacement' => '[REDACTED]',
            'mark_redacted' => false,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => ['enabled' => false],
        ]);

        $result = app(Redactor::class)->redact(['note' => catastrophicSubject()], 'pcre');

        // Before: preg_match returned false, was read as "no match", and the
        // value went out untouched.
        expect($result['note'])->toBe('[REDACTED]');
    });

    it('does not let an unevaluatable exclusion pattern excuse a high-entropy value', function () {
        ini_set('pcre.backtrack_limit', '1000');

        $secret = 'Zx7Qm4Kd9Rb2Vn6Tp1Ws8Yc3Hf5Jg0Lz';

        config()->set('redactor.profiles.pcre_exclusion', [
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
                'threshold' => 3.0,
                'min_length' => 10,
                // An exclusion pattern that cannot be evaluated against this
                // subject must not be read as "excluded".
                'exclusion_patterns' => ['/^(x+)+y$/'],
            ],
        ]);

        $result = app(Redactor::class)->redact(['token' => $secret], 'pcre_exclusion');

        expect($result['token'])->toBe('[REDACTED]');
    });

    it('treats an unevaluatable blocked-key pattern as blocking the key', function () {
        ini_set('pcre.backtrack_limit', '1');

        config()->set('redactor.profiles.pcre_keys', [
            'enabled' => true,
            'strategies' => [BlockedKeysStrategy::class],
            'safe_keys' => [],
            'blocked_keys' => ['*secret*'],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => false,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => ['enabled' => false],
        ]);

        $result = app(Redactor::class)->redact([str_repeat('deep_', 400).'secret' => 'value'], 'pcre_keys');

        expect(array_values($result)[0])->toBe('[REDACTED]');
    });
});

describe('Pcre helper', function () {
    afterEach(function () {
        ini_restore('pcre.backtrack_limit');
    });

    it('reports a normal match and non-match correctly', function () {
        expect(Pcre::matches('/foo/', 'a foo b', onError: true))->toBeTrue()
            ->and(Pcre::matches('/foo/', 'a bar b', onError: true))->toBeFalse();
    });

    it('returns the caller-chosen answer on engine failure', function () {
        ini_set('pcre.backtrack_limit', '1000');

        expect(Pcre::matches(catastrophicPattern(), catastrophicSubject(), onError: true))->toBeTrue()
            ->and(Pcre::matches(catastrophicPattern(), catastrophicSubject(), onError: false))->toBeFalse();
    });

    it('returns null from replaceCallback when the engine fails', function () {
        ini_set('pcre.backtrack_limit', '1000');

        $out = Pcre::replaceCallback(
            catastrophicPattern(),
            fn (array $m) => '[X]',
            catastrophicSubject()
        );

        expect($out)->toBeNull();
    });

    it('replaces normally when the engine succeeds', function () {
        expect(Pcre::replaceCallback('/\d+/', fn (array $m) => '#', 'a1b22c'))->toBe('a#b#c');
    });

    it('recognises invalid patterns without emitting a PHP warning', function () {
        expect(Pcre::isValidPattern('/valid/'))->toBeTrue()
            ->and(Pcre::isValidPattern('/[unclosed/'))->toBeFalse();
    });
});
