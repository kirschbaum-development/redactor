<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Strategies\BlockedKeysStrategy;
use Kirschbaum\Redactor\Strategies\Contracts\PreservingStrategy;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;
use Kirschbaum\Redactor\Strategies\SafeKeysStrategy;

function safeKeyProfile(array $overrides = []): array
{
    return array_merge([
        'enabled' => true,
        'strategies' => [SafeKeysStrategy::class, BlockedKeysStrategy::class, RegexPatternsStrategy::class],
        'safe_keys' => ['trace_id'],
        'blocked_keys' => ['password', '*token*'],
        'patterns' => ['email' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/'],
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

describe('Safe key semantics', function () {
    it('preserves a scalar under a safe key', function () {
        config()->set('redactor.profiles.safe', safeKeyProfile());

        expect(app(Redactor::class)->redact(['trace_id' => 'abc-123'], 'safe'))
            ->toBe(['trace_id' => 'abc-123']);
    });

    it('preserves the whole subtree under a safe key', function () {
        config()->set('redactor.profiles.safe', safeKeyProfile(['safe_keys' => ['debug_dump']]));

        // Preservation is now recursive and deliberate. Previously the walk
        // descended anyway, because the engine compared value identity to
        // decide whether a strategy had handled the value - so "safe" meant
        // one thing for a scalar and the opposite for an array.
        $result = app(Redactor::class)->redact([
            'debug_dump' => ['password' => 'hunter2', 'nested' => ['api_token' => 'abc']],
        ], 'safe');

        expect($result['debug_dump'])->toBe([
            'password' => 'hunter2',
            'nested' => ['api_token' => 'abc'],
        ]);
    });

    it('still redacts the same keys when they are not under a safe key', function () {
        config()->set('redactor.profiles.safe', safeKeyProfile(['safe_keys' => ['debug_dump']]));

        expect(app(Redactor::class)->redact(['other' => ['password' => 'hunter2']], 'safe'))
            ->toBe(['other' => ['password' => '[REDACTED]']]);
    });

    it('matches safe keys case-insensitively', function () {
        config()->set('redactor.profiles.safe', safeKeyProfile(['safe_keys' => ['trace_id']]));

        expect(app(Redactor::class)->redact(['TRACE_ID' => 'abc'], 'safe'))
            ->toBe(['TRACE_ID' => 'abc']);
    });

    it('does not treat a whole-array check as a safe key', function () {
        // redactArray() evaluates the array itself with an empty key. An empty
        // key must never match a safe key, or a stray '' entry would preserve
        // the entire payload.
        config()->set('redactor.profiles.safe', safeKeyProfile(['safe_keys' => ['']]));

        expect(app(Redactor::class)->redact(['password' => 'hunter2'], 'safe'))
            ->toBe(['password' => '[REDACTED]']);
    });

    it('declares SafeKeysStrategy as preserving', function () {
        expect(new SafeKeysStrategy)->toBeInstanceOf(PreservingStrategy::class);
    });
});

describe('Shipped default profile safe keys', function () {
    it('no longer waves free-text and PII fields through', function () {
        $safe = RedactorConfig::fromConfig('default')->safeKeys;

        // Each of these used to be safe, so the value was emitted verbatim no
        // matter what it contained.
        expect($safe)->not->toContain('message')
            ->and($safe)->not->toContain('title')
            ->and($safe)->not->toContain('url')
            ->and($safe)->not->toContain('path')
            ->and($safe)->not->toContain('ip')
            ->and($safe)->not->toContain('user_agent')
            ->and($safe)->not->toContain('source')
            ->and($safe)->not->toContain('target');
    });

    it('actually redacts an email in a message field now', function () {
        // The headline symptom: with 'message' safe, this address was emitted
        // in full while the identical string under any other key was redacted.
        $result = app(Redactor::class)->redact([
            'message' => 'User bob@example.com failed to authenticate',
        ], 'default');

        expect($result['message'])->toBe('User [REDACTED] failed to authenticate');
    });

    it('redacts credentials embedded in a url', function () {
        $result = app(Redactor::class)->redact([
            'url' => 'https://admin:s3cr3t@internal.example.com/reports',
        ], 'default');

        expect($result['url'])->not->toContain('s3cr3t');
    });

    it('keeps genuinely structural keys safe', function () {
        $safe = RedactorConfig::fromConfig('default')->safeKeys;

        expect($safe)->toContain('id')
            ->and($safe)->toContain('uuid')
            ->and($safe)->toContain('trace_id')
            ->and($safe)->toContain('created_at')
            ->and($safe)->toContain('level');
    });

    it('has no key in both safe_keys and blocked_keys in any shipped profile', function () {
        foreach (RedactorConfig::getAvailableProfiles() as $profile) {
            $config = RedactorConfig::fromConfig($profile);

            // session_id was in both lists in the default profile. SafeKeys
            // runs first, so the blocked_keys entry was dead configuration.
            expect(array_intersect($config->safeKeys, $config->blockedKeys))
                ->toBe([], "profile [{$profile}] lists keys as both safe and blocked");
        }
    });
});

describe('redactor:validate catches safe/blocked conflicts', function () {
    it('fails when a profile lists a key as both safe and blocked', function () {
        config()->set('redactor.profiles.conflicted', safeKeyProfile([
            'safe_keys' => ['session_id'],
            'blocked_keys' => ['session_id'],
        ]));

        $this->artisan('redactor:validate')
            ->expectsOutputToContain('conflicted')
            ->assertFailed();
    });
});
