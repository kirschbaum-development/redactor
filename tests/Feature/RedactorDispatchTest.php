<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Strategies\LargeObjectStrategy;
use Kirschbaum\Redactor\Strategies\RedactionStrategyInterface;

/**
 * Counts how many times the chain is asked about a value, and with which keys.
 */
class CountingStrategy implements RedactionStrategyInterface
{
    /** @var array<int, string> */
    public static array $keys = [];

    public static function reset(): void
    {
        self::$keys = [];
    }

    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        self::$keys[] = $key;

        return false;
    }

    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        return $value;
    }
}

function dispatchProfile(array $overrides = []): array
{
    return array_merge([
        'enabled' => true,
        'strategies' => ['counting'],
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

describe('Strategy dispatch', function () {
    beforeEach(function () {
        CountingStrategy::reset();
        config()->set('redactor.custom_strategies', ['counting' => CountingStrategy::class]);
        config()->set('redactor.profiles.dispatch', dispatchProfile());
    });

    it('evaluates each node exactly once', function () {
        // {a: {b: {c: 1}}} is four nodes: the root, a, b and c. redactArray()
        // used to re-run the chain on every nested array with an empty key,
        // after the parent loop had already run it with the real key - six
        // dispatches for four nodes.
        app(Redactor::class)->redact(['a' => ['b' => ['c' => 1]]], 'dispatch');

        expect(CountingStrategy::$keys)->toBe(['', 'a', 'b', 'c']);
    });

    it('evaluates a wider tree once per node', function () {
        app(Redactor::class)->redact([
            'x' => ['p' => 1, 'q' => 2],
            'y' => ['r' => ['s' => 3]],
        ], 'dispatch');

        // root, x, p, q, y, r, s
        expect(CountingStrategy::$keys)->toHaveCount(7);
    });

    it('evaluates the root once for a top-level array', function () {
        app(Redactor::class)->redact(['only' => 'value'], 'dispatch');

        expect(CountingStrategy::$keys)->toBe(['', 'only']);
    });

    it('still evaluates the root array as a whole so LargeObjectStrategy applies', function () {
        config()->set('redactor.profiles.dispatch_large', dispatchProfile([
            'strategies' => [LargeObjectStrategy::class],
            'redact_large_objects' => true,
            'max_object_size' => 3,
        ]));

        $result = app(Redactor::class)->redact(['a' => 1, 'b' => 2, 'c' => 3, 'd' => 4], 'dispatch_large');

        expect($result)->toHaveKey('_large_object_redacted');
    });

    it('still evaluates a nested array as a whole so LargeObjectStrategy applies', function () {
        config()->set('redactor.profiles.dispatch_large', dispatchProfile([
            'strategies' => [LargeObjectStrategy::class],
            'redact_large_objects' => true,
            'max_object_size' => 3,
        ]));

        $result = app(Redactor::class)->redact([
            'small' => ['a' => 1],
            'big' => ['a' => 1, 'b' => 2, 'c' => 3, 'd' => 4],
        ], 'dispatch_large');

        expect($result['big'])->toHaveKey('_large_object_redacted')
            ->and($result['small'])->toBe(['a' => 1]);
    });

    it('does not skip the chain for a scalar', function () {
        app(Redactor::class)->redact('a bare string', 'dispatch');

        expect(CountingStrategy::$keys)->toBe(['']);
    });
});
