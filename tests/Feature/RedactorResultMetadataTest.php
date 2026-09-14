<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\RedactionResult;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Strategies\BlockedKeysStrategy;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;

function metadataProfile(array $overrides = []): array
{
    return array_merge([
        'enabled' => true,
        'strategies' => [BlockedKeysStrategy::class, RegexPatternsStrategy::class],
        'safe_keys' => [],
        'blocked_keys' => ['password'],
        'patterns' => ['email' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/'],
        'replacement' => '[REDACTED]',
        'mark_redacted' => true,
        'track_redacted_keys' => true,
        'non_redactable_object_behavior' => 'preserve',
        'max_value_length' => null,
        'redact_large_objects' => false,
        'max_object_size' => 100,
        'shannon_entropy' => ['enabled' => false],
    ], $overrides);
}

describe('Redaction metadata kept out of the payload', function (): void {
    beforeEach(function (): void {
        config()->set('redactor.profiles.meta', metadataProfile());
    });

    it('reports what happened without touching the value', function (): void {
        $result = resolve(Redactor::class)->inspect(
            ['password' => 'hunter2', 'keep' => 'visible'],
            'meta'
        );

        expect($result)->toBeInstanceOf(RedactionResult::class)
            ->and($result->wasRedacted)->toBeTrue()
            ->and($result->redactedKeys)->toBe(['password']);
    });

    it('reports a clean payload as untouched', function (): void {
        $result = resolve(Redactor::class)->inspect(['keep' => 'visible'], 'meta');

        expect($result->wasRedacted)->toBeFalse()
            ->and($result->redactedKeys)->toBe([])
            ->and($result->value)->toBe(['keep' => 'visible']);
    });

    it('carries metadata for a bare string, which markers never could', function (): void {
        $result = resolve(Redactor::class)->inspect('mail bob@example.com', 'meta');

        expect($result->value)->toBe('mail [REDACTED]')
            ->and($result->wasRedacted)->toBeTrue();
    });

    it('reports metadata even when mark_redacted is off', function (): void {
        config()->set('redactor.profiles.meta', metadataProfile(['mark_redacted' => false]));

        $result = resolve(Redactor::class)->inspect(['password' => 'x'], 'meta');

        expect($result->value)->toBe(['password' => '[REDACTED]'])
            ->and($result->wasRedacted)->toBeTrue()
            ->and($result->redactedKeys)->toBe(['password']);
    });

    it('reports a disabled profile as untouched rather than redacted', function (): void {
        config()->set('redactor.profiles.meta', metadataProfile(['enabled' => false]));

        $result = resolve(Redactor::class)->inspect(['password' => 'x'], 'meta');

        expect($result->wasRedacted)->toBeFalse()
            ->and($result->value)->toBe(['password' => 'x']);
    });

    it('keeps redact() returning the bare value', function (): void {
        expect(resolve(Redactor::class)->redact(['keep' => 'visible'], 'meta'))
            ->toBe(['keep' => 'visible']);
    });
});

describe('Legacy markers no longer corrupt the payload', function (): void {
    beforeEach(function (): void {
        config()->set('redactor.profiles.meta', metadataProfile());
    });

    it('leaves a list a list', function (): void {
        // Adding '_redacted' to a list turns it into a JSON object, breaking
        // any consumer with an array schema:
        //   ["a@b.com","x@y.com"] -> {"0":"...","1":"...","_redacted":true}
        $result = resolve(Redactor::class)->redact(['a@b.com', 'x@y.com'], 'meta');

        expect($result)->toBe(['[REDACTED]', '[REDACTED]'])
            ->and(array_is_list($result))->toBeTrue()
            ->and(json_encode($result))->toBe('["[REDACTED]","[REDACTED]"]');
    });

    it('still reports the redaction for a list through the result object', function (): void {
        $result = resolve(Redactor::class)->inspect(['a@b.com'], 'meta');

        expect($result->wasRedacted)->toBeTrue()
            ->and($result->value)->toBe(['[REDACTED]']);
    });

    it('does not overwrite a caller key named _redacted', function (): void {
        // Previously the caller's value was silently replaced with `true`.
        $result = resolve(Redactor::class)->redact([
            'password' => 'x',
            '_redacted' => 'user-data-here',
        ], 'meta');

        expect($result['_redacted'])->toBe('user-data-here')
            ->and($result['password'])->toBe('[REDACTED]');
    });

    it('does not overwrite a caller key named _redacted_keys', function (): void {
        $result = resolve(Redactor::class)->redact([
            'password' => 'x',
            '_redacted_keys' => ['mine'],
        ], 'meta');

        expect($result['_redacted_keys'])->toBe(['mine']);
    });

    it('still adds markers to an ordinary associative payload', function (): void {
        $result = resolve(Redactor::class)->redact(['password' => 'x', 'keep' => 'y'], 'meta');

        expect($result['_redacted'])->toBeTrue()
            ->and($result['_redacted_keys'])->toBe(['password'])
            ->and($result['keep'])->toBe('y');
    });

    it('adds markers to an empty array so the flag is not lost', function (): void {
        // An empty array is technically a list; treating it as one would drop
        // the marker for a payload whose contents were removed entirely.
        config()->set('redactor.profiles.meta', metadataProfile([
            'blocked_keys' => [],
            'patterns' => [],
            'strategies' => [BlockedKeysStrategy::class],
        ]));

        $result = resolve(Redactor::class)->inspect([], 'meta');

        expect($result->wasRedacted)->toBeFalse()
            ->and($result->value)->toBe([]);
    });

    it('omits _redacted_keys when tracking is disabled', function (): void {
        config()->set('redactor.profiles.meta', metadataProfile(['track_redacted_keys' => false]));

        $result = resolve(Redactor::class)->redact(['password' => 'x'], 'meta');

        expect($result)->toHaveKey('_redacted')
            ->and($result)->not->toHaveKey('_redacted_keys');
    });
});
