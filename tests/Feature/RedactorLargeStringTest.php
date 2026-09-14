<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Strategies\LargeStringStrategy;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;

function largeStringProfile(array $overrides = []): array
{
    return array_merge([
        'enabled' => true,
        'strategies' => [LargeStringStrategy::class, RegexPatternsStrategy::class],
        'safe_keys' => [],
        'blocked_keys' => [],
        'patterns' => ['email' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/'],
        'replacement' => '[REDACTED]',
        'mark_redacted' => false,
        'track_redacted_keys' => false,
        'non_redactable_object_behavior' => 'preserve',
        'max_value_length' => 40,
        'redact_large_objects' => false,
        'max_object_size' => null,
        'shannon_entropy' => ['enabled' => false],
    ], $overrides);
}

describe('Long strings', function (): void {
    beforeEach(function (): void {
        config()->set('redactor.profiles.long', largeStringProfile());
    });

    it('keeps the head of a long string and notes what was cut', function (): void {
        $value = str_repeat('trace line. ', 10); // 120 bytes

        $result = resolve(Redactor::class)->inspect($value, 'long');

        expect($result->value)->toStartWith(substr($value, 0, 40))
            ->and($result->value)->toEndWith('[REDACTED] (String truncated: 120 characters, 40 kept)')
            ->and($result->wasRedacted)->toBeTrue()
            ->and($result->findings[0]->rule)->toBe('large_string')
            ->and($result->findings[0]->offset)->toBe(40)
            ->and($result->findings[0]->length)->toBe(80);
    });

    it('still scans the head it keeps', function (): void {
        $value = 'contact bob@example.com about '.str_repeat('x', 100);

        $result = resolve(Redactor::class)->redact($value, 'long');

        expect($result)->toStartWith('contact [REDACTED] about ')
            ->and($result)->not->toContain('bob@example.com');
    });

    it('never splits a multibyte character at the cut', function (): void {
        $value = str_repeat('é', 30); // 60 bytes, limit is 40

        $result = resolve(Redactor::class)->redact($value, 'long');

        $head = explode(' [REDACTED]', $result)[0];

        expect(mb_check_encoding($head, 'UTF-8'))->toBeTrue()
            ->and($head)->toBe(str_repeat('é', 20));
    });

    it('replaces the whole value when the behaviour is redact', function (): void {
        config()->set('redactor.profiles.long.large_string_behavior', 'redact');

        $result = resolve(Redactor::class)->redact(str_repeat('a', 100), 'long');

        expect($result)->toBe('[REDACTED] (String with 100 characters)');
    });

    it('rejects an unknown behaviour', function (): void {
        config()->set('redactor.profiles.long.large_string_behavior', 'shrug');

        resolve(Redactor::class)->redact('x', 'long');
    })->throws(\InvalidArgumentException::class, 'large_string_behavior');

    it('leaves strings at or under the limit alone', function (): void {
        $value = str_repeat('a', 40);

        expect(resolve(Redactor::class)->redact($value, 'long'))->toBe($value);
    });
});
