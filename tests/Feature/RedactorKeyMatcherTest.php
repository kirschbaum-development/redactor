<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Strategies\BlockedKeysStrategy;
use Kirschbaum\Redactor\Support\KeyMatcher;

function blockedProfile(array $blockedKeys): array
{
    return [
        'enabled' => true,
        'strategies' => [BlockedKeysStrategy::class],
        'safe_keys' => [],
        'blocked_keys' => $blockedKeys,
        'patterns' => [],
        'replacement' => '[REDACTED]',
        'mark_redacted' => false,
        'track_redacted_keys' => false,
        'non_redactable_object_behavior' => 'preserve',
        'max_value_length' => null,
        'redact_large_objects' => false,
        'max_object_size' => 100,
        'shannon_entropy' => ['enabled' => false],
    ];
}

describe('KeyMatcher pattern shapes', function () {
    afterEach(fn () => KeyMatcher::flush());

    it('matches exact names case-insensitively', function () {
        $matcher = KeyMatcher::for(['password']);

        expect($matcher->matches('password'))->toBeTrue()
            ->and($matcher->matches('PASSWORD'))->toBeTrue()
            ->and($matcher->matches('Password'))->toBeTrue()
            ->and($matcher->matches('password_hint'))->toBeFalse();
    });

    it('matches contains patterns', function () {
        $matcher = KeyMatcher::for(['*token*']);

        expect($matcher->matches('token'))->toBeTrue()
            ->and($matcher->matches('api_token'))->toBeTrue()
            ->and($matcher->matches('token_data'))->toBeTrue()
            ->and($matcher->matches('my_TOKEN_field'))->toBeTrue()
            ->and($matcher->matches('tokn'))->toBeFalse();
    });

    it('matches prefix patterns', function () {
        $matcher = KeyMatcher::for(['password*']);

        expect($matcher->matches('password'))->toBeTrue()
            ->and($matcher->matches('password_confirmation'))->toBeTrue()
            ->and($matcher->matches('user_password'))->toBeFalse();
    });

    it('matches suffix patterns', function () {
        $matcher = KeyMatcher::for(['*_key']);

        expect($matcher->matches('private_key'))->toBeTrue()
            ->and($matcher->matches('signing_key'))->toBeTrue()
            ->and($matcher->matches('key_id'))->toBeFalse();
    });

    it('matches multi-wildcard patterns via the regex path', function () {
        $matcher = KeyMatcher::for(['user_*_token']);

        expect($matcher->matches('user_api_token'))->toBeTrue()
            ->and($matcher->matches('user_auth_token'))->toBeTrue()
            ->and($matcher->matches('user_token'))->toBeFalse()
            ->and($matcher->matches('admin_api_token'))->toBeFalse();
    });

    it('treats a lone asterisk as matching everything', function () {
        $matcher = KeyMatcher::for(['*']);

        expect($matcher->matches('anything'))->toBeTrue()
            ->and($matcher->matches('x'))->toBeTrue();
    });

    it('never matches the empty key', function () {
        expect(KeyMatcher::for(['*'])->matches(''))->toBeFalse()
            ->and(KeyMatcher::for([''])->matches(''))->toBeFalse();
    });

    it('reports an empty pattern list as empty and matches nothing', function () {
        $matcher = KeyMatcher::for([]);

        expect($matcher->isEmpty())->toBeTrue()
            ->and($matcher->matches('password'))->toBeFalse();
    });

    it('combines exact and wildcard patterns in one list', function () {
        $matcher = KeyMatcher::for(['password', '*token*', 'user_*_data']);

        expect($matcher->matches('password'))->toBeTrue()
            ->and($matcher->matches('api_token'))->toBeTrue()
            ->and($matcher->matches('user_profile_data'))->toBeTrue()
            ->and($matcher->matches('normal_field'))->toBeFalse();
    });

    it('reuses the compiled matcher for an identical pattern list', function () {
        expect(KeyMatcher::for(['a', '*b*']))->toBe(KeyMatcher::for(['a', '*b*']))
            ->and(KeyMatcher::for(['a', '*b*']))->not->toBe(KeyMatcher::for(['a', '*c*']));
    });
});

describe('Blocked keys behaviour is unchanged by compilation', function () {
    afterEach(fn () => KeyMatcher::flush());

    it('matches the same keys through the full redactor', function () {
        config()->set('redactor.profiles.blocked', blockedProfile([
            'password',
            '*token*',
            '*key*',
            'user_*_data',
        ]));

        $result = app(Redactor::class)->redact([
            'user_id' => 123,
            'api_token' => 'secret123',
            'access_token' => 'abc123',
            'my_custom_token' => 'xyz789',
            'user_api_key' => 'key123',
            'private_key_data' => 'private',
            'password' => 'secret',
            'user_profile_data' => 'profile',
            'user_settings_data' => 'settings',
            'normal_field' => 'safe_value',
        ], 'blocked');

        expect($result)->toBe([
            'user_id' => 123,
            'api_token' => '[REDACTED]',
            'access_token' => '[REDACTED]',
            'my_custom_token' => '[REDACTED]',
            'user_api_key' => '[REDACTED]',
            'private_key_data' => '[REDACTED]',
            'password' => '[REDACTED]',
            'user_profile_data' => '[REDACTED]',
            'user_settings_data' => '[REDACTED]',
            'normal_field' => 'safe_value',
        ]);
    });

    it('picks up a changed blocked_keys list rather than serving a stale matcher', function () {
        config()->set('redactor.profiles.blocked', blockedProfile(['password']));

        expect(app(Redactor::class)->redact(['secret' => 'v'], 'blocked'))
            ->toBe(['secret' => 'v']);

        config()->set('redactor.profiles.blocked', blockedProfile(['password', 'secret']));

        expect(app(Redactor::class)->redact(['secret' => 'v'], 'blocked'))
            ->toBe(['secret' => '[REDACTED]']);
    });
});
