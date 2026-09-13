<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Strategies\BlockedKeysStrategy;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;
use Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy;
use Kirschbaum\Redactor\Support\AllowList;

function allowProfile(array $overrides = []): array
{
    return array_merge([
        'enabled' => true,
        'strategies' => [BlockedKeysStrategy::class, RegexPatternsStrategy::class, ShannonEntropyStrategy::class],
        'safe_keys' => [],
        'blocked_keys' => ['password'],
        'patterns' => [
            'email' => ['pattern' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/', 'entity' => 'email'],
        ],
        'paths' => ['meta.contact' => 'redact'],
        'allowlist' => ['noreply@example.com', '/^test-\d+@example\.com$/'],
        'replacement' => '[REDACTED]',
        'mark_redacted' => false,
        'track_redacted_keys' => false,
        'non_redactable_object_behavior' => 'preserve',
        'max_value_length' => null,
        'redact_large_objects' => false,
        'max_object_size' => 100,
        'shannon_entropy' => ['enabled' => true, 'threshold' => 4.0, 'min_length' => 20, 'exclusion_patterns' => []],
    ], $overrides);
}

describe('Profile allowlist', function () {
    beforeEach(fn () => config()->set('redactor.profiles.allow', allowProfile()));

    it('lets an allowed value through a pattern', function () {
        expect(app(Redactor::class)->redact('from noreply@example.com and bob@example.com', 'allow'))
            ->toBe('from noreply@example.com and [REDACTED]');
    });

    it('compares literals case-insensitively and ignores surrounding whitespace', function () {
        expect(app(Redactor::class)->redact('from NoReply@Example.COM', 'allow'))
            ->toBe('from NoReply@Example.COM');
    });

    it('accepts a regex entry', function () {
        expect(app(Redactor::class)->redact('test-42@example.com and test-x@example.com', 'allow'))
            ->toBe('test-42@example.com and [REDACTED]');
    });

    it('lets an allowed value through a blocked key', function () {
        config()->set('redactor.profiles.allow.allowlist', ['changeme']);

        $result = app(Redactor::class)->redact(['password' => 'changeme', 'other' => ['password' => 'hunter2']], 'allow');

        expect($result['password'])->toBe('changeme')
            ->and($result['other']['password'])->toBe('[REDACTED]');
    });

    it('lets an allowed value through a path rule', function () {
        config()->set('redactor.profiles.allow.allowlist', ['support']);

        $result = app(Redactor::class)->redact(['meta' => ['contact' => 'support']], 'allow');

        expect($result['meta']['contact'])->toBe('support');
    });

    it('lets an allowed value through the entropy detector', function () {
        config()->set('redactor.profiles.allow.allowlist', ['Zx7Qm4Kd9Rb2Vn6Tp1Ws8Yc3Hf']);

        expect(app(Redactor::class)->redact('key Zx7Qm4Kd9Rb2Vn6Tp1Ws8Yc3Hf ok', 'allow'))
            ->toBe('key Zx7Qm4Kd9Rb2Vn6Tp1Ws8Yc3Hf ok');
    });

    it('does not report an allowed value as a finding', function () {
        $result = app(Redactor::class)->redactWithMetadata('noreply@example.com', 'allow');

        expect($result->wasRedacted)->toBeFalse()
            ->and($result->findings)->toBe([]);
    });

    it('never lets an unevaluatable regex entry allow anything', function () {
        $list = AllowList::for(['/^\p{L}+$/u']);

        expect($list->allows("\xff\xfe"))->toBeFalse();
    });

    it('treats a string that merely starts with a slash as a literal', function () {
        $list = AllowList::for(['/var/log/app.log']);

        expect($list->allows('/var/log/app.log'))->toBeTrue()
            ->and($list->allows('/var/log/other.log'))->toBeFalse();
    });
});

describe('Per-rule allow', function () {
    it('scopes the exception to the rule that declares it', function () {
        config()->set('redactor.profiles.allow', allowProfile([
            'allowlist' => [],
            'patterns' => [
                'email' => [
                    'pattern' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/',
                    'allow' => ['/@example\.com$/'],
                ],
                'token' => ['pattern' => '/tok_[a-z0-9]+/'],
            ],
            'shannon_entropy' => ['enabled' => false],
        ]));

        expect(app(Redactor::class)->redact('bob@example.com bob@customer.com tok_abc', 'allow'))
            ->toBe('bob@example.com [REDACTED] [REDACTED]');
    });
});

describe('Dictionary rules', function () {
    it('redacts any listed word, longest first, case-insensitively', function () {
        config()->set('redactor.profiles.allow', allowProfile([
            'allowlist' => [],
            'patterns' => [
                'codenames' => ['words' => ['Project Falcon', 'Falcon', 'Orion'], 'entity' => 'codename'],
            ],
            'shannon_entropy' => ['enabled' => false],
        ]));

        expect(app(Redactor::class)->redact('status of project falcon and ORION', 'allow'))
            ->toBe('status of [REDACTED] and [REDACTED]');
    });

    it('does not match inside a longer word', function () {
        config()->set('redactor.profiles.allow', allowProfile([
            'allowlist' => [],
            'patterns' => ['codenames' => ['words' => ['Orion']]],
            'shannon_entropy' => ['enabled' => false],
        ]));

        expect(app(Redactor::class)->redact('Orionids are meteors', 'allow'))->toBe('Orionids are meteors');
    });

    it('rejects an empty word list', function () {
        config()->set('redactor.profiles.allow', allowProfile([
            'patterns' => ['codenames' => ['words' => []]],
        ]));

        app(Redactor::class)->redact('x', 'allow');
    })->throws(\InvalidArgumentException::class, 'words');
});

describe('Entropy tokenising stays flat in memory', function () {
    it('holds only tokens long enough to qualify', function () {
        config()->set('redactor.profiles.allow', allowProfile([
            'patterns' => [],
            'blocked_keys' => [],
            'shannon_entropy' => ['enabled' => true, 'threshold' => 4.8, 'min_length' => 25, 'exclusion_patterns' => []],
        ]));

        $subject = str_repeat('lorem ipsum dolor sit amet consectetur ', 25_000); // ~1 MB of short words
        $redactor = app(Redactor::class);
        $redactor->redact('warm up', 'allow');

        memory_reset_peak_usage();
        $before = memory_get_peak_usage();
        $redactor->redact($subject, 'allow');
        $delta = memory_get_peak_usage() - $before;

        // Every token is under min_length, so nothing should be collected at
        // all; a few hundred KB of scratch is fine, ten times the input is not.
        expect($delta)->toBeLessThan(strlen($subject));
    });
});
