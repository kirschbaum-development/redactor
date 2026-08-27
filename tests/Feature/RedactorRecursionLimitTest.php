<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Strategies\BlockedKeysStrategy;

/**
 * An object whose toArray() hands back a reference to itself. Eloquent models
 * with an inverse relation loaded, and hand-rolled DTOs that expose a parent
 * pointer, both produce this shape in ordinary logging code.
 */
class SelfReferencingDto
{
    public function toArray(): array
    {
        return ['self' => $this, 'password' => 'hunter2'];
    }
}

/**
 * Two objects that reference each other rather than themselves.
 */
class PingDto
{
    public ?object $partner = null;

    public function toArray(): array
    {
        return ['partner' => $this->partner, 'token' => 'abc'];
    }
}

/**
 * Returns the same child object twice. This is not a cycle and must not be
 * mistaken for one.
 */
class RepeatedChildDto
{
    public function __construct(private object $child) {}

    public function toArray(): array
    {
        return ['first' => $this->child, 'second' => $this->child];
    }
}

class LeafDto
{
    public function toArray(): array
    {
        return ['password' => 'leaf-secret', 'keep' => 'visible'];
    }
}

function recursionProfile(array $overrides = []): array
{
    return array_merge([
        'enabled' => true,
        'strategies' => [BlockedKeysStrategy::class],
        'safe_keys' => [],
        'blocked_keys' => ['password', '*token*'],
        'patterns' => [],
        'replacement' => '[REDACTED]',
        'mark_redacted' => false,
        'track_redacted_keys' => false,
        'non_redactable_object_behavior' => 'preserve',
        'max_value_length' => null,
        'redact_large_objects' => false,
        'max_object_size' => 100,
        'max_depth' => 32,
        'shannon_entropy' => ['enabled' => false],
    ], $overrides);
}

describe('Recursion limits', function () {
    beforeEach(function () {
        config()->set('redactor.profiles.recursion', recursionProfile());
    });

    it('breaks a self-referencing toArray() instead of exhausting memory', function () {
        // Before the depth budget and cycle check existed, this exhausted the
        // 128 MB memory limit and killed the process with a fatal error.
        $result = app(Redactor::class)->redact(['dto' => new SelfReferencingDto], 'recursion');

        expect($result)->toBeArray()
            ->and($result['dto'])->toBeArray()
            ->and($result['dto']['self'])->toContain('Circular reference')
            ->and($result['dto']['self'])->toContain(SelfReferencingDto::class)
            ->and($result['dto']['password'])->toBe('[REDACTED]');
    });

    it('breaks a two-object reference cycle', function () {
        $a = new PingDto;
        $b = new PingDto;
        $a->partner = $b;
        $b->partner = $a;

        $result = app(Redactor::class)->redact(['a' => $a], 'recursion');

        expect($result['a']['partner']['partner'])->toContain('Circular reference')
            ->and($result['a']['token'])->toBe('[REDACTED]');
    });

    it('still walks the same object twice when it is repeated, not cyclic', function () {
        $result = app(Redactor::class)->redact(
            ['parent' => new RepeatedChildDto(new LeafDto)],
            'recursion'
        );

        // Both branches must be fully redacted; neither may be mistaken for a
        // cycle just because the same instance appears more than once.
        expect($result['parent']['first']['password'])->toBe('[REDACTED]')
            ->and($result['parent']['first']['keep'])->toBe('visible')
            ->and($result['parent']['second']['password'])->toBe('[REDACTED]')
            ->and($result['parent']['second']['keep'])->toBe('visible');
    });

    it('replaces anything deeper than max_depth', function () {
        config()->set('redactor.profiles.recursion', recursionProfile(['max_depth' => 4]));

        $payload = ['password' => 'top'];
        for ($i = 0; $i < 10; $i++) {
            $payload = ['nested' => $payload];
        }

        $result = app(Redactor::class)->redact($payload, 'recursion');

        $json = json_encode($result);

        expect($json)->toContain('Max depth of 4 exceeded')
            // The cut-off replaces the subtree, so the deep secret never
            // appears in the output at all.
            ->and($json)->not->toContain('top');
    });

    it('leaves payloads shallower than max_depth completely intact', function () {
        config()->set('redactor.profiles.recursion', recursionProfile(['max_depth' => 6]));

        $result = app(Redactor::class)->redact([
            'a' => ['b' => ['c' => ['d' => ['keep' => 'value', 'password' => 'x']]]],
        ], 'recursion');

        expect($result['a']['b']['c']['d']['keep'])->toBe('value')
            ->and($result['a']['b']['c']['d']['password'])->toBe('[REDACTED]')
            ->and(json_encode($result))->not->toContain('Max depth');
    });

    it('survives a deeply nested payload that would previously blow the stack', function () {
        $payload = 'leaf';
        for ($i = 0; $i < 20_000; $i++) {
            $payload = ['n' => $payload];
        }

        $before = memory_get_usage();
        $result = app(Redactor::class)->redact($payload, 'recursion');
        $growth = (memory_get_usage() - $before) / 1_048_576;

        expect(json_encode($result))->toContain('Max depth of 32 exceeded')
            // The walk stops at 32 levels, so memory does not track input depth.
            ->and($growth)->toBeLessThan(16.0);
    });

    it('marks the payload as redacted when the depth limit trips', function () {
        config()->set('redactor.profiles.recursion', recursionProfile([
            'max_depth' => 2,
            'mark_redacted' => true,
        ]));

        $result = app(Redactor::class)->redact(
            ['a' => ['b' => ['c' => ['harmless' => 'value']]]],
            'recursion'
        );

        expect($result)->toHaveKey('_redacted')
            ->and($result['_redacted'])->toBeTrue();
    });

    it('defaults max_depth when a profile does not set one', function () {
        $profile = recursionProfile();
        unset($profile['max_depth']);
        config()->set('redactor.profiles.recursion_default', $profile);

        expect(RedactorConfig::fromConfig('recursion_default')->maxDepth)
            ->toBe(RedactorConfig::DEFAULT_MAX_DEPTH);
    });

    it('rejects a non-positive max_depth', function () {
        config()->set('redactor.profiles.recursion_bad', recursionProfile(['max_depth' => 0]));

        expect(fn () => RedactorConfig::fromConfig('recursion_bad'))
            ->toThrow(\InvalidArgumentException::class, 'profiles.recursion_bad.max_depth');
    });
});
