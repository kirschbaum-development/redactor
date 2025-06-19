<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Redactor;

describe('Redactor Wildcard Blocked Keys Tests', function () {
    it('matches wildcard patterns for blocked keys', function () {
        // Configure a test profile with wildcard patterns
        config()->set('redactor.default_profile', 'wildcard_test');
        config()->set('redactor.profiles.wildcard_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => ['*token*', '*key*', 'password'],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => ['enabled' => false],
        ]);

        $redactor = new Redactor;

        $context = [
            'user_id' => 123,
            'api_token' => 'secret_token_123',
            'access_token' => 'access_value',
            'my_custom_token' => 'custom_value',
            'jwt_token_data' => 'jwt_data',
            'user_api_key' => 'key_123',
            'private_key_data' => 'private_data',
            'some_key_value' => 'key_data',
            'password' => 'exact_match',
            'normal_field' => 'should_stay',
        ];

        $result = $redactor->redact($context);

        // Wildcard *token* should match all token-containing keys
        expect($result['api_token'])->toBe('[REDACTED]')
            ->and($result['access_token'])->toBe('[REDACTED]')
            ->and($result['my_custom_token'])->toBe('[REDACTED]')
            ->and($result['jwt_token_data'])->toBe('[REDACTED]')
            // Wildcard *key* should match all key-containing keys
            ->and($result['user_api_key'])->toBe('[REDACTED]')
            ->and($result['private_key_data'])->toBe('[REDACTED]')
            ->and($result['some_key_value'])->toBe('[REDACTED]')
            // Exact match should still work
            ->and($result['password'])->toBe('[REDACTED]')
            // Non-matching keys should remain unchanged
            ->and($result['user_id'])->toBe(123)
            ->and($result['normal_field'])->toBe('should_stay')
            ->and($result['_redacted'])->toBeTrue();
    });

    it('supports exact matches alongside wildcard patterns', function () {
        config()->set('redactor.default_profile', 'wildcard_test');
        config()->set('redactor.profiles.wildcard_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => ['exact_match', '*partial*'],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => ['enabled' => false],
        ]);

        $redactor = new Redactor;

        $context = [
            'exact_match' => 'should_be_redacted',
            'not_exact_match' => 'should_stay',
            'partial_start' => 'should_be_redacted',
            'end_partial' => 'should_be_redacted',
            'has_partial_inside' => 'should_be_redacted',
            'other_field' => 'should_stay',
        ];

        $result = $redactor->redact($context);

        expect($result['exact_match'])->toBe('[REDACTED]')
            ->and($result['partial_start'])->toBe('[REDACTED]')
            ->and($result['end_partial'])->toBe('[REDACTED]')
            ->and($result['has_partial_inside'])->toBe('[REDACTED]')
            ->and($result['not_exact_match'])->toBe('should_stay')
            ->and($result['other_field'])->toBe('should_stay');
    });

    it('handles case-insensitive wildcard matching', function () {
        config()->set('redactor.default_profile', 'wildcard_test');
        config()->set('redactor.profiles.wildcard_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => ['*TOKEN*'],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => ['enabled' => false],
        ]);

        $redactor = new Redactor;

        $context = [
            'API_TOKEN' => 'uppercase',
            'api_token' => 'lowercase',
            'Api_Token' => 'mixed_case',
            'MyTokenData' => 'camel_case',
            'other_field' => 'should_stay',
        ];

        $result = $redactor->redact($context);

        expect($result['API_TOKEN'])->toBe('[REDACTED]')
            ->and($result['api_token'])->toBe('[REDACTED]')
            ->and($result['Api_Token'])->toBe('[REDACTED]')
            ->and($result['MyTokenData'])->toBe('[REDACTED]')
            ->and($result['other_field'])->toBe('should_stay');
    });

    it('supports multiple wildcard positions', function () {
        config()->set('redactor.default_profile', 'wildcard_test');
        config()->set('redactor.profiles.wildcard_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => ['user_*_token', '*_key_*'],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => ['enabled' => false],
        ]);

        $redactor = new Redactor;

        $context = [
            'user_api_token' => 'should_match',
            'user_auth_token' => 'should_match',
            'user_token' => 'should_not_match',
            'api_token' => 'should_not_match',
            'my_key_data' => 'should_match',
            'the_key_value' => 'should_match',
            'key_data' => 'should_not_match',
            'other_field' => 'should_stay',
        ];

        $result = $redactor->redact($context);

        expect($result['user_api_token'])->toBe('[REDACTED]')
            ->and($result['user_auth_token'])->toBe('[REDACTED]')
            ->and($result['my_key_data'])->toBe('[REDACTED]')
            ->and($result['the_key_value'])->toBe('[REDACTED]')
            ->and($result['user_token'])->toBe('should_not_match')
            ->and($result['api_token'])->toBe('should_not_match')
            ->and($result['key_data'])->toBe('should_not_match')
            ->and($result['other_field'])->toBe('should_stay');
    });
});
