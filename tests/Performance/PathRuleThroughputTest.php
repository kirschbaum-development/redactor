<?php

declare(strict_types=1);

use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Strategies\BlockedKeysStrategy;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;
use Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy;

function apiPayload(): array
{
    return [
        'request' => [
            'method' => 'POST',
            'path' => '/v1/orders',
            'headers' => [
                'authorization' => 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.abcdefgh',
                'user_agent' => 'Mozilla/5.0',
                'accept' => 'application/json',
                'x_request_id' => 'req_01H8XYZ',
            ],
        ],
        'user' => ['id' => 42, 'email' => 'alice@customer.com', 'name' => 'Alice'],
        'items' => array_map(fn (int $i) => [
            'sku' => "SKU-{$i}",
            'qty' => $i,
            'note' => 'an ordinary line of descriptive text',
        ], range(1, 20)),
    ];
}

function timeProfile(string $profile, int $iterations = 400): float
{
    $redactor = app(Redactor::class);
    $payload = apiPayload();

    $redactor->redact($payload, $profile);

    $start = hrtime(true);
    for ($i = 0; $i < $iterations; $i++) {
        $redactor->redact($payload, $profile);
    }

    return (hrtime(true) - $start) / $iterations;
}

function throughputProfile(array $overrides): array
{
    return array_merge([
        'enabled' => true,
        'strategies' => [BlockedKeysStrategy::class, RegexPatternsStrategy::class, ShannonEntropyStrategy::class],
        'safe_keys' => [],
        'blocked_keys' => ['password', '*token*', '*secret*', '*key*', 'authorization'],
        'patterns' => [
            'email' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/',
            'jwt' => '/eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+/',
            'phone' => '/\b\d{3}[.-]?\d{3}[.-]?\d{4}\b/',
        ],
        'paths' => [],
        'operators' => ['default' => 'redact'],
        'replacement' => '[REDACTED]',
        'mark_redacted' => false,
        'track_redacted_keys' => false,
        'non_redactable_object_behavior' => 'preserve',
        'max_value_length' => null,
        'redact_large_objects' => false,
        'max_object_size' => 1000,
        'shannon_entropy' => [
            'enabled' => true,
            'threshold' => 4.5,
            'min_length' => 20,
            'exclusion_patterns' => [],
        ],
    ], $overrides);
}

describe('Path rules as a fast lane', function () {
    it('is faster than scanning the same payload for the same values', function () {
        // Same payload, same two things removed. One profile finds them by
        // scanning every string; the other is told where they are.
        config()->set('redactor.profiles.by_scanning', throughputProfile([]));

        config()->set('redactor.profiles.by_path', throughputProfile([
            // Nothing to scan for: the locations are known.
            'blocked_keys' => [],
            'patterns' => [],
            'shannon_entropy' => ['enabled' => false],
            'paths' => [
                'request.headers.authorization' => 'redact',
                'user.email' => 'redact',
            ],
        ]));

        $scanning = timeProfile('by_scanning');
        $paths = timeProfile('by_path');

        // Both must actually redact the same two values, or the comparison is
        // meaningless.
        $scanned = app(Redactor::class)->redact(apiPayload(), 'by_scanning');
        $pathed = app(Redactor::class)->redact(apiPayload(), 'by_path');

        expect($scanned['request']['headers']['authorization'])->toBe('[REDACTED]')
            ->and($pathed['request']['headers']['authorization'])->toBe('[REDACTED]')
            ->and($scanned['user']['email'])->toBe('[REDACTED]')
            ->and($pathed['user']['email'])->toBe('[REDACTED]')
            ->and($paths)->toBeLessThan($scanning);
    });

    it('costs almost nothing when no path rule can match', function () {
        // An exhausted cursor stops being consulted, so a profile carrying path
        // rules that never fire should not pay much for them.
        config()->set('redactor.profiles.no_paths', throughputProfile([]));
        config()->set('redactor.profiles.dead_paths', throughputProfile([
            'paths' => [
                'nothing.here.at.all' => 'redact',
                'also.not.this' => 'redact',
                'or.this.one.either' => 'redact',
            ],
        ]));

        $without = timeProfile('no_paths');
        $with = timeProfile('dead_paths');

        expect($with)->toBeLessThan($without * 1.5);
    });

    it('does not slow down as the number of path rules grows', function () {
        // The trie is walked in lockstep with the payload, so cost tracks the
        // rules currently in play - not how many were configured.
        $few = ['request.headers.authorization' => 'redact'];

        $many = $few;
        for ($i = 0; $i < 200; $i++) {
            $many["unused_{$i}.deep.path.{$i}"] = 'redact';
        }

        config()->set('redactor.profiles.few_paths', throughputProfile([
            'blocked_keys' => [], 'patterns' => [], 'shannon_entropy' => ['enabled' => false],
            'paths' => $few,
        ]));
        config()->set('redactor.profiles.many_paths', throughputProfile([
            'blocked_keys' => [], 'patterns' => [], 'shannon_entropy' => ['enabled' => false],
            'paths' => $many,
        ]));

        $few = timeProfile('few_paths');
        $many = timeProfile('many_paths');

        // 200x the rules for well under 2x the time.
        expect($many)->toBeLessThan($few * 2.0);
    });
})->skip(runningWithCoverage(), 'Timings are meaningless under coverage instrumentation.');
