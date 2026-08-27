<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Strategies\BlockedKeysStrategy;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;

function copyProfile(array $overrides = []): array
{
    return array_merge([
        'enabled' => true,
        'strategies' => [BlockedKeysStrategy::class, RegexPatternsStrategy::class],
        'safe_keys' => [],
        'blocked_keys' => ['password'],
        'patterns' => ['email' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/'],
        'paths' => [],
        'operators' => ['default' => 'redact'],
        'replacement' => '[REDACTED]',
        'mark_redacted' => false,
        'track_redacted_keys' => false,
        'non_redactable_object_behavior' => 'preserve',
        'max_value_length' => null,
        'redact_large_objects' => false,
        'max_object_size' => 1000,
        'shannon_entropy' => ['enabled' => false],
    ], $overrides);
}

describe('Returning the input when nothing changed', function () {
    beforeEach(fn () => config()->set('redactor.profiles.copy', copyProfile()));

    it('returns a clean payload exactly as it arrived', function () {
        $payload = [
            'level' => 'info',
            'nested' => ['a' => 1, 'b' => ['c' => 'text']],
            'list' => [1, 2, 3],
        ];

        expect(app(Redactor::class)->redact($payload, 'copy'))->toBe($payload);
    });

    it('preserves key order and key types', function () {
        $payload = ['z' => 1, 'a' => 2, 3 => 'three', 'm' => 4];

        $result = app(Redactor::class)->redact($payload, 'copy');

        expect(array_keys($result))->toBe(array_keys($payload))
            ->and($result)->toBe($payload);
    });

    it('keeps a list a list', function () {
        $payload = ['a', 'b', 'c'];

        $result = app(Redactor::class)->redact($payload, 'copy');

        expect(array_is_list($result))->toBeTrue()
            ->and($result)->toBe($payload);
    });

    it('still redacts, and only what it should', function () {
        $result = app(Redactor::class)->redact([
            'keep' => 'ordinary',
            'password' => 'hunter2',
            'nested' => ['keep' => 'also ordinary', 'mail' => 'a@b.com'],
        ], 'copy');

        expect($result)->toBe([
            'keep' => 'ordinary',
            'password' => '[REDACTED]',
            'nested' => ['keep' => 'also ordinary', 'mail' => '[REDACTED]'],
        ]);
    });

    it('leaves untouched siblings alone when one branch changes', function () {
        $payload = [
            'untouched' => ['deep' => ['value' => 'nothing here']],
            'touched' => ['password' => 'hunter2'],
        ];

        $result = app(Redactor::class)->redact($payload, 'copy');

        expect($result['untouched'])->toBe($payload['untouched'])
            ->and($result['touched'])->toBe(['password' => '[REDACTED]']);
    });

    it('preserves order when a key is removed', function () {
        config()->set('redactor.profiles.copy', copyProfile([
            'paths' => ['b' => 'remove'],
        ]));

        $result = app(Redactor::class)->redact(['a' => 1, 'b' => 2, 'c' => 3], 'copy');

        expect($result)->toBe(['a' => 1, 'c' => 3])
            ->and(array_keys($result))->toBe(['a', 'c']);
    });

    it('removes a list entry without renumbering the rest', function () {
        config()->set('redactor.profiles.copy', copyProfile([
            'paths' => ['1' => 'remove'],
        ]));

        $result = app(Redactor::class)->redact(['zero', 'one', 'two'], 'copy');

        expect($result)->toBe([0 => 'zero', 2 => 'two']);
    });

    it('does not report a redaction for an untouched payload', function () {
        $result = app(Redactor::class)->redactWithMetadata(['a' => 'clean', 'b' => ['c' => 'also clean']], 'copy');

        expect($result->wasRedacted)->toBeFalse()
            ->and($result->findings)->toBe([]);
    });

    it('handles an empty array and an empty nested array', function () {
        expect(app(Redactor::class)->redact([], 'copy'))->toBe([])
            ->and(app(Redactor::class)->redact(['a' => []], 'copy'))->toBe(['a' => []]);
    });

    it('does not mutate the array it was given', function () {
        $payload = ['password' => 'hunter2', 'keep' => 'ordinary'];
        $before = $payload;

        app(Redactor::class)->redact($payload, 'copy');

        expect($payload)->toBe($before);
    });
});
