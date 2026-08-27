<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Scanner\Scanner;
use Kirschbaum\Redactor\Strategies\BlockedKeysStrategy;
use Kirschbaum\Redactor\Strategies\RedactionStrategyInterface;
use Kirschbaum\Redactor\Strategies\SafeKeysStrategy;

function singletonProfile(array $overrides = []): array
{
    return array_merge([
        'enabled' => true,
        'strategies' => [BlockedKeysStrategy::class],
        'safe_keys' => [],
        'blocked_keys' => ['password'],
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

describe('Redactor container binding', function () {
    it('resolves the redactor as a singleton', function () {
        expect(app(Redactor::class))->toBe(app(Redactor::class));
    });

    it('resolves the scanner as a singleton sharing that redactor', function () {
        expect(app(Scanner::class))->toBe(app(Scanner::class));
    });

    it('reuses strategy instances across calls for the same profile', function () {
        config()->set('redactor.profiles.singleton_a', singletonProfile());

        $redactor = app(Redactor::class);

        $first = $redactor->getStrategies('singleton_a');
        $second = $redactor->getStrategies('singleton_a');

        expect($first)->toHaveCount(1)
            ->and($first[0])->toBe($second[0]);
    });

    it('rebuilds strategies when a profile changes its strategy list', function () {
        config()->set('redactor.profiles.singleton_b', singletonProfile());

        $redactor = app(Redactor::class);

        expect($redactor->getStrategies('singleton_b'))->toHaveCount(1);

        config()->set('redactor.profiles.singleton_b', singletonProfile([
            'strategies' => [SafeKeysStrategy::class, BlockedKeysStrategy::class],
        ]));

        $rebuilt = $redactor->getStrategies('singleton_b');

        expect($rebuilt)->toHaveCount(2)
            ->and($rebuilt[0])->toBeInstanceOf(SafeKeysStrategy::class);
    });

    it('picks up custom strategies registered after the redactor was constructed', function () {
        $redactor = app(Redactor::class);

        // Force construction (and, previously, eager custom-strategy loading)
        // before the custom strategy is configured.
        $redactor->getAvailableProfiles();

        config()->set('redactor.custom_strategies', [
            'late_strategy' => LateRegisteredStrategy::class,
        ]);
        config()->set('redactor.profiles.singleton_c', singletonProfile([
            'strategies' => ['late_strategy'],
        ]));

        expect($redactor->redact(['anything' => 'value'], 'singleton_c'))
            ->toBe(['anything' => 'LATE']);
    });
});

class LateRegisteredStrategy implements RedactionStrategyInterface
{
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        return is_string($value);
    }

    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        $context->markRedacted();

        return 'LATE';
    }
}
