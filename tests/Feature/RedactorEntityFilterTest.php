<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Detection\EntityFilter;
use Kirschbaum\Redactor\Facades\Redactor;
use Kirschbaum\Redactor\Findings\MatchFinding;

function entityFilterPayload(): array
{
    return [
        'email' => 'bob@example.com',
        'password' => 'hunter2',
        'note' => 'card 4111111111111111 for alice@example.com, token sk_live_4eC39HqLyjWDarjtT1zdp7dc',
    ];
}

describe('Per-call entity filtering', function (): void {
    it('acts only on the entities asked for', function (): void {
        $result = Redactor::profile('default')->only(['email'])->withoutMarkers()->redact(entityFilterPayload());

        expect($result)->toBe([
            'email' => '[REDACTED]',
            'password' => 'hunter2',
            'note' => 'card 4111111111111111 for [REDACTED], token sk_live_4eC39HqLyjWDarjtT1zdp7dc',
        ]);
    });

    it('skips the entities excluded', function (): void {
        $result = Redactor::profile('default')->except(['email', 'credit_card'])->withoutMarkers()->redact(entityFilterPayload());

        expect($result['email'])->toBe('bob@example.com')
            ->and($result['password'])->toBe('[REDACTED]')
            ->and($result['note'])->toBe('card 4111111111111111 for alice@example.com, token [REDACTED]');
    });

    it('treats a key rule\'s entity as the key name', function (): void {
        $result = Redactor::profile('default')->only(['password'])->withoutMarkers()->redact(entityFilterPayload());

        expect($result['password'])->toBe('[REDACTED]')
            ->and($result['email'])->toBe('bob@example.com');
    });

    it('applies to path rules by the key they land on', function (): void {
        config()->set('redactor.profiles.default.paths', ['meta.token' => 'redact', 'meta.note' => 'redact']);

        $result = Redactor::profile('default')->only(['note'])->withoutMarkers()
            ->redact(['meta' => ['token' => 'abc', 'note' => 'n']]);

        expect($result['meta'])->toBe(['token' => 'abc', 'note' => '[REDACTED]']);
    });

    it('reports only the findings it acted on', function (): void {
        $result = Redactor::profile('default')->only(['credit_card'])->inspect(entityFilterPayload());

        expect(array_unique(array_map(fn (MatchFinding $f): string => $f->entity(), $result->findings)))->toBe(['credit_card'])
            ->and($result->redactedKeys)->toBe(['note']);
    });

    it('compares entities case-insensitively and composes only with except', function (): void {
        $filter = EntityFilter::all()->only(['Email', 'CREDIT_CARD'])->except(['credit_card']);

        expect($filter->allows('email'))->toBeTrue()
            ->and($filter->allows('credit_card'))->toBeFalse()
            ->and($filter->allows('password'))->toBeFalse()
            ->and($filter->allowsEverything())->toBeFalse()
            ->and(EntityFilter::all()->allowsEverything())->toBeTrue();
    });

    it('never lets a filter suppress a fail-closed detection', function (): void {
        config()->set('redactor.profiles.default.patterns', ['bad' => '/^\p{L}+$/u']);

        expect(Redactor::profile('default')->only(['nothing'])->redact("\xff\xfe"))->toBe('[REDACTED]');
    });

    it('is recorded by the fake', function (): void {
        $fake = Redactor::fake();

        Redactor::profile('default')->only(['email'])->redact(entityFilterPayload());

        $fake->assertRedacted('email');
        $fake->assertNotRedacted('password');
    });
});
