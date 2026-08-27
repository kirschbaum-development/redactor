<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Strategies\BlockedKeysStrategy;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;
use Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy;
use Kirschbaum\Redactor\Support\Pcre;

/**
 * Malformed UTF-8 against a /u pattern is the one PCRE failure that behaves
 * identically on every build: preg_match() returns false with
 * PREG_BAD_UTF8_ERROR, and preg_replace_callback() returns null.
 *
 * Backtrack-limit exhaustion is not usable as a probe. Whether a given pattern
 * blows the limit depends on the PCRE2 version, its auto-possessification, and
 * whether JIT is compiled in - a probe that reliably failed on one PHP 8.5
 * build matched cleanly on another.
 */
function failingPattern(): string
{
    return '/^\p{L}+$/u';
}

function failingSubject(): string
{
    return "\xff\xfe not valid utf-8";
}

describe('PCRE failures fail closed', function () {
    it('sanity check: the probe really does make the engine give up', function () {
        // Without this the tests below could pass for the wrong reason - a
        // pattern that simply matched would look identical.
        $raw = @preg_match(failingPattern(), failingSubject());

        expect($raw)->toBeFalse()
            ->and(preg_last_error())->toBe(PREG_BAD_UTF8_ERROR);
    });

    it('treats an unevaluatable detection pattern as a match', function () {
        config()->set('redactor.profiles.pcre', [
            'enabled' => true,
            'strategies' => [RegexPatternsStrategy::class],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => ['unevaluatable' => failingPattern()],
            'replacement' => '[REDACTED]',
            'mark_redacted' => false,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => ['enabled' => false],
        ]);

        $result = app(Redactor::class)->redact(['note' => failingSubject()], 'pcre');

        // Before: preg_match returned false, was read as "no match", and the
        // value went out untouched.
        expect($result['note'])->toBe('[REDACTED]');
    });

    it('does not let an unevaluatable exclusion pattern excuse a value', function () {
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
                'exclusion_patterns' => [failingPattern()],
            ],
        ]);

        $excluded = (new ShannonEntropyStrategy)->isCommonPattern(
            failingSubject(),
            RedactorConfig::fromConfig('pcre_exclusion')
        );

        expect($excluded)->toBeFalse();
    });

    it('replaces a value the entropy tokeniser cannot even split', function () {
        config()->set('redactor.profiles.pcre_entropy', [
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
                'exclusion_patterns' => [],
            ],
        ]);

        $result = app(Redactor::class)->redact(
            ['note' => failingSubject()."\xfe high entropy Zx7Qm4Kd9Rb2Vn6Tp1Ws8Yc3Hf"],
            'pcre_entropy'
        );

        expect($result['note'])->toBe('[REDACTED]');
    });

    it('treats an unevaluatable blocked-key pattern as blocking the key', function () {
        config()->set('redactor.profiles.pcre_keys', [
            'enabled' => true,
            'strategies' => [BlockedKeysStrategy::class],
            'safe_keys' => [],
            'blocked_keys' => ['*'.failingSubject().'*'],
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

        // A *contains* pattern is compiled to str_contains, which cannot fail,
        // so this asserts the safe-by-construction path rather than the
        // fail-closed one. The regex branch is covered by the Pcre tests below.
        $result = app(Redactor::class)->redact(['a'.failingSubject().'b' => 'value'], 'pcre_keys');

        expect(array_values($result)[0])->toBe('[REDACTED]');
    });
});

describe('Pcre helper', function () {
    it('reports a normal match and non-match correctly', function () {
        expect(Pcre::matches('/foo/', 'a foo b', onError: true))->toBeTrue()
            ->and(Pcre::matches('/foo/', 'a bar b', onError: true))->toBeFalse();
    });

    it('returns the caller-chosen answer on engine failure', function () {
        expect(Pcre::matches(failingPattern(), failingSubject(), onError: true))->toBeTrue()
            ->and(Pcre::matches(failingPattern(), failingSubject(), onError: false))->toBeFalse();
    });

    it('returns null from replaceCallback when the engine fails', function () {
        $out = Pcre::replaceCallback(
            failingPattern(),
            fn (array $m) => '[X]',
            failingSubject()
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
