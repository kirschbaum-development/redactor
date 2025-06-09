<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy;

describe('Shannon Entropy Strategy Tests', function () {
    it('redacts high entropy strings like API keys', function () {
        // Explicit profile for high entropy test
        config()->set('redactor.default_profile', 'entropy_test');
        config()->set('redactor.profiles.entropy_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.0,
                'min_length' => 20,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'api_key' => 'sk-1234567890abcdef1234567890abcdef12345678', // High entropy, long
            'simple_text' => 'this is a simple text message that is long enough', // Low entropy, long
            'short_random' => 'abc123', // High entropy but too short
        ];

        $result = $redactor->redact($context);

        expect($result['api_key'])->toBe('[REDACTED]')
            ->and($result['simple_text'])->toBe('this is a simple text message that is long enough')
            ->and($result['short_random'])->toBe('abc123')
            ->and($result['_redacted'])->toBeTrue();
    });

    it('can be disabled via configuration', function () {
        // Explicit profile with Shannon entropy disabled
        config()->set('redactor.default_profile', 'entropy_disabled_test');
        config()->set('redactor.profiles.entropy_disabled_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => false,
                'threshold' => 4.0,
                'min_length' => 20,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'api_key' => 'sk-1234567890abcdef1234567890abcdef12345678',
        ];

        $result = $redactor->redact($context);

        expect($result['api_key'])->toBe('sk-1234567890abcdef1234567890abcdef12345678')
            ->and($result)->not->toHaveKey('_redacted');
    });

    it('respects minimum length threshold', function () {
        // Explicit profile with higher min_length
        config()->set('redactor.default_profile', 'min_length_test');
        config()->set('redactor.profiles.min_length_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.0,
                'min_length' => 50,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'short_key' => 'sk-1234567890abcdef', // High entropy but under min_length
            'long_key' => 'sk-ABCabc123XYZxyz789DEFdef456GHIghi0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', // High entropy and over min_length (70 chars)
        ];

        $result = $redactor->redact($context);

        expect($result['short_key'])->toBe('sk-1234567890abcdef')
            ->and($result['long_key'])->toBe('[REDACTED]')
            ->and($result['_redacted'])->toBeTrue();
    });

    it('respects entropy threshold', function () {
        // Explicit profile with very high threshold
        config()->set('redactor.default_profile', 'high_threshold_test');
        config()->set('redactor.profiles.high_threshold_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 6.0, // Very high threshold
                'min_length' => 20,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'medium_entropy' => 'sk-1234567890abcdef1234567890abcdef12345678',
            'very_high_entropy' => 'x9z8y7w6v5u4t3s2r1q0p9o8n7m6l5k4j3h2g1f0e9d8c7b6a5',
        ];

        $result = $redactor->redact($context);

        // With very high threshold, even high-entropy strings might not be redacted
        expect($result['medium_entropy'])->toBe('sk-1234567890abcdef1234567890abcdef12345678');
    });

    it('allows long hex strings to bypass exclusion patterns', function () {
        // Explicit profile with hex exclusion pattern
        config()->set('redactor.default_profile', 'hex_pattern_test');
        config()->set('redactor.profiles.hex_pattern_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 3.0, // Low threshold
                'min_length' => 10,
                'exclusion_patterns' => ['/^[0-9a-f]+$/i'], // Hex pattern
            ],
        ]);

        $redactor = new Redactor;

        // Create a long hex string (>= 32 chars) that should continue past the pattern match
        $longHex = str_repeat('a1b2c3d4', 8); // 64 characters, all hex

        $data = ['long_hex' => $longHex];
        $result = $redactor->redact($data);

        // The long hex string should be redacted despite matching hex pattern
        expect($result['long_hex'])->toBe('[REDACTED]')
            ->and($result['_redacted'])->toBeTrue();

        // Verify short hex is NOT redacted (normal pattern matching)
        $shortHex = 'a1b2c3d4e5f6'; // 12 characters, hex
        $shortResult = $redactor->redact(['short_hex' => $shortHex]);
        expect($shortResult['short_hex'])->toBe('a1b2c3d4e5f6') // Not redacted
            ->and($shortResult)->not->toHaveKey('_redacted');
    });
});

describe('Shannon Entropy Common Pattern Detection Tests', function () {
    it('skips common patterns despite high entropy', function () {
        // Explicit profile with default exclusion patterns
        config()->set('redactor.default_profile', 'common_patterns_test');
        config()->set('redactor.profiles.common_patterns_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 3.0,
                'min_length' => 10,
                'exclusion_patterns' => [
                    '/^https?:\/\//',
                    '/^[\/\\\\].+[\/\\\\]/',
                    '/^\d{4}-\d{2}-\d{2}/',
                    '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i',
                    '/^[0-9a-f]+$/i',
                    '/^\s*$/',
                ],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'url' => 'https://api.example.com/v1/users/123?token=abc123def456ghi789',
            'uuid' => '550e8400-e29b-41d4-a716-446655440000',
            'date' => '2023-12-25T15:30:45.123Z',
            'file_path' => '/usr/local/bin/some-random-executable-name',
            'short_hex' => 'abc123def',
        ];

        $result = $redactor->redact($context);

        // All should be preserved as they match common patterns
        expect($result['url'])->toBe('https://api.example.com/v1/users/123?token=abc123def456ghi789')
            ->and($result['uuid'])->toBe('550e8400-e29b-41d4-a716-446655440000')
            ->and($result['date'])->toBe('2023-12-25T15:30:45.123Z')
            ->and($result['file_path'])->toBe('/usr/local/bin/some-random-executable-name')
            ->and($result['short_hex'])->toBe('abc123def')
            ->and($result)->not->toHaveKey('_redacted');
    });

    it('skips short hexadecimal hashes', function () {
        // Explicit profile for hex testing
        config()->set('redactor.default_profile', 'hex_test');
        config()->set('redactor.profiles.hex_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 3.0, // Low threshold to test hex bypass
                'min_length' => 5,
                'exclusion_patterns' => ['/^[0-9a-f]+$/i'],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'short_hex_1' => 'abc123',           // 6 chars, hex
            'short_hex_2' => '1234567890abcdef', // 16 chars, hex
            'short_hex_3' => 'deadbeef',         // 8 chars, hex
            'mixed_case_hex' => 'AbC123DeF',     // Mixed case hex
            'not_hex' => 'xyz123',               // Not pure hex
            'long_hex' => '1234567890abcdef1234567890abcdef12', // 34 chars, should potentially be redacted
        ];

        $result = $redactor->redact($context);

        // Short hex strings should be preserved despite high entropy
        expect($result['short_hex_1'])->toBe('abc123')
            ->and($result['short_hex_2'])->toBe('1234567890abcdef')
            ->and($result['short_hex_3'])->toBe('deadbeef')
            ->and($result['mixed_case_hex'])->toBe('AbC123DeF')
            ->and($result['not_hex'])->toBe('xyz123') // Not pure hex, not redacted due to low entropy
            ->and($result['long_hex'])->toBe('[REDACTED]'); // Long hex might be redacted if high entropy
    });

    it('skips whitespace-only strings', function () {
        // Explicit profile for whitespace testing
        config()->set('redactor.default_profile', 'whitespace_test');
        config()->set('redactor.profiles.whitespace_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 0.1, // Very low threshold
                'min_length' => 1,
                'exclusion_patterns' => ['/^\s*$/'],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'empty_string' => '',
            'spaces_only' => '   ',
            'tabs_only' => "\t\t\t",
            'mixed_whitespace' => " \t \n \r ",
            'newlines_only' => "\n\n\n",
            'single_space' => ' ',
        ];

        $result = $redactor->redact($context);

        // All whitespace strings should be preserved
        expect($result['empty_string'])->toBe('')
            ->and($result['spaces_only'])->toBe('   ')
            ->and($result['tabs_only'])->toBe("\t\t\t")
            ->and($result['mixed_whitespace'])->toBe(" \t \n \r ")
            ->and($result['newlines_only'])->toBe("\n\n\n")
            ->and($result['single_space'])->toBe(' ')
            ->and($result)->not->toHaveKey('_redacted');
    });

    it('skips IPv4 addresses', function () {
        // Explicit profile for IP testing
        config()->set('redactor.default_profile', 'ip_test');
        config()->set('redactor.profiles.ip_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 3.0, // Low threshold to test IP bypass
                'min_length' => 7,
                'exclusion_patterns' => ['/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/'],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'ip_1' => '192.168.1.1',
            'ip_2' => '10.0.0.1',
            'ip_3' => '172.16.254.1',
            'ip_4' => '255.255.255.255',
            'not_ip' => '999.999.999.999', // Invalid IP but matches pattern
            'partial_ip' => '192.168.1',     // Incomplete IP
        ];

        $result = $redactor->redact($context);

        // Valid IPs should be preserved
        expect($result['ip_1'])->toBe('192.168.1.1')
            ->and($result['ip_2'])->toBe('10.0.0.1')
            ->and($result['ip_3'])->toBe('172.16.254.1')
            ->and($result['ip_4'])->toBe('255.255.255.255')
            ->and($result['not_ip'])->toBe('999.999.999.999') // Matches pattern even if invalid
            ->and($result['partial_ip'])->toBe('192.168.1') // Doesn't match pattern, but low entropy
            ->and($result)->not->toHaveKey('_redacted');
    });

    it('skips MAC addresses', function () {
        // Explicit profile for MAC testing
        config()->set('redactor.default_profile', 'mac_test');
        config()->set('redactor.profiles.mac_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 3.0, // Low threshold to test MAC bypass
                'min_length' => 10,
                'exclusion_patterns' => ['/^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i'],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'mac_1' => '00:1B:44:11:3A:B7',
            'mac_2' => 'aa:bb:cc:dd:ee:ff',
            'mac_3' => 'AA:BB:CC:DD:EE:FF',
            'not_mac' => '00:1B:44:11:3A',     // Incomplete MAC
            'invalid_mac' => '00:1B:44:11:3A:GG', // Invalid hex
        ];

        $result = $redactor->redact($context);

        // Valid MACs should be preserved
        expect($result['mac_1'])->toBe('00:1B:44:11:3A:B7')
            ->and($result['mac_2'])->toBe('aa:bb:cc:dd:ee:ff')
            ->and($result['mac_3'])->toBe('AA:BB:CC:DD:EE:FF')
            ->and($result['not_mac'])->toBe('00:1B:44:11:3A') // Doesn't match pattern
            ->and($result['invalid_mac'])->toBe('00:1B:44:11:3A:GG') // Doesn't match pattern
            ->and($result)->not->toHaveKey('_redacted');
    });

    it('validates isCommonPattern method directly', function () {
        // Explicit profile for direct method testing
        config()->set('redactor.default_profile', 'direct_method_test');
        config()->set('redactor.profiles.direct_method_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.0,
                'min_length' => 10,
                'exclusion_patterns' => [
                    '/^https?:\/\//',
                    '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i',
                ],
            ],
        ]);

        $redactor = new Redactor;
        $config = RedactorConfig::fromConfig();

        // Test URL pattern
        expect($redactor->isCommonPattern('https://example.com', $config))->toBeTrue()
            ->and($redactor->isCommonPattern('http://test.org', $config))->toBeTrue()
            ->and($redactor->isCommonPattern('ftp://example.com', $config))->toBeFalse();

        // Test UUID pattern
        expect($redactor->isCommonPattern('550e8400-e29b-41d4-a716-446655440000', $config))->toBeTrue()
            ->and($redactor->isCommonPattern('not-a-uuid-string', $config))->toBeFalse();
    });

    it('uses custom entropy exclusion patterns from configuration', function () {
        // Explicit profile with custom exclusion patterns
        config()->set('redactor.default_profile', 'custom_patterns_test');
        config()->set('redactor.profiles.custom_patterns_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 3.0,
                'min_length' => 10,
                'exclusion_patterns' => [
                    '/^custom_prefix_/',
                    '/special_[0-9]+_suffix$/',
                ],
            ],
        ]);

        $redactor = new Redactor;

        $context = [
            'custom_1' => 'custom_prefix_abc123def456ghi789jkl012',
            'custom_2' => 'some_random_text_special_12345_suffix',
            'not_custom' => 'abc123def456ghi789jkl012mno345pqr678',
        ];

        $result = $redactor->redact($context);

        // Custom patterns should be preserved
        expect($result['custom_1'])->toBe('custom_prefix_abc123def456ghi789jkl012')
            ->and($result['custom_2'])->toBe('some_random_text_special_12345_suffix')
            ->and($result['not_custom'])->toBe('[REDACTED]') // High entropy, no pattern match
            ->and($result['_redacted'])->toBeTrue();
    });

    it('covers specific lines 103 and 108 in ShannonEntropyStrategy', function () {
        // Create strategy instance directly to test specific method calls
        $strategy = new \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy;

        // Test line 103: return false when exclusion_patterns is not an array
        $config1 = new \Kirschbaum\Redactor\RedactorConfig(
            enabled: true,
            safeKeys: [],
            blockedKeys: [],
            patterns: [],
            replacement: '[REDACTED]',
            markRedacted: true,
            trackRedactedKeys: false,
            nonRedactableObjectBehavior: 'preserve',
            maxValueLength: null,
            redactLargeObjects: true,
            maxObjectSize: 100,
            shannonEntropy: [
                'enabled' => true,
                'threshold' => 3.0,
                'min_length' => 5,
                'exclusion_patterns' => 'not_an_array', // This triggers line 103
            ],
            strategies: [],
            profile: 'test'
        );
        $context1 = new \Kirschbaum\Redactor\RedactionContext($config1);

        // Use reflection to call isCommonPattern directly
        $reflection = new \ReflectionClass($strategy);
        $method = $reflection->getMethod('isCommonPattern');
        $method->setAccessible(true);

        // This should hit line 103: return false (exclusion_patterns not array)
        $result1 = $method->invoke($strategy, 'test string', $context1);
        expect($result1)->toBeFalse();

        // Test line 108: continue when pattern is not a string
        $config2 = new \Kirschbaum\Redactor\RedactorConfig(
            enabled: true,
            safeKeys: [],
            blockedKeys: [],
            patterns: [],
            replacement: '[REDACTED]',
            markRedacted: true,
            trackRedactedKeys: false,
            nonRedactableObjectBehavior: 'preserve',
            maxValueLength: null,
            redactLargeObjects: true,
            maxObjectSize: 100,
            shannonEntropy: [
                'enabled' => true,
                'threshold' => 3.0,
                'min_length' => 5,
                'exclusion_patterns' => [
                    123, // Non-string pattern - triggers line 108 continue
                    null, // Non-string pattern
                    '/valid_pattern/', // Valid pattern at the end
                ],
            ],
            strategies: [],
            profile: 'test'
        );
        $context2 = new \Kirschbaum\Redactor\RedactionContext($config2);

        // This should hit line 108: continue (non-string patterns skipped)
        $result2 = $method->invoke($strategy, 'valid_pattern', $context2);
        expect($result2)->toBeTrue(); // Should match the valid pattern after skipping non-strings
    });
});

describe('Shannon Entropy Algorithm Tests', function () {
    it('calculates entropy correctly', function () {
        // Explicit profile for entropy calculation testing
        config()->set('redactor.default_profile', 'entropy_calc_test');
        config()->set('redactor.profiles.entropy_calc_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.0,
                'min_length' => 1,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        // Test known entropy values
        expect($redactor->calculateShannonEntropy('aaaa'))->toBe(0.0) // All same character
            ->and($redactor->calculateShannonEntropy('abcd'))->toBeGreaterThan(1.9) // Perfect distribution
            ->and($redactor->calculateShannonEntropy('abcd'))->toBeLessThan(2.1) // Perfect distribution
            ->and($redactor->calculateShannonEntropy('a'))->toBe(0.0) // Single character
            ->and($redactor->calculateShannonEntropy(''))->toBe(0.0); // Empty string
    });

    it('handles edge cases in entropy calculation', function () {
        // Explicit profile for edge case testing
        config()->set('redactor.default_profile', 'entropy_edge_test');
        config()->set('redactor.profiles.entropy_edge_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.0,
                'min_length' => 1,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        // Edge cases
        expect($redactor->calculateShannonEntropy(''))->toBe(0.0)
            ->and($redactor->calculateShannonEntropy('a'))->toBe(0.0)
            ->and($redactor->calculateShannonEntropy('aa'))->toBe(0.0)
            ->and($redactor->calculateShannonEntropy('ab'))->toBeGreaterThan(0.9)
            ->and($redactor->calculateShannonEntropy('ab'))->toBeLessThan(1.1);

        // Unicode characters
        $unicodeEntropy = $redactor->calculateShannonEntropy('αβγδ');
        expect($unicodeEntropy)->toBeGreaterThan(1.9)
            ->and($unicodeEntropy)->toBeLessThan(2.1);
    });

    it('returns zero entropy when no ShannonEntropyStrategy is found during entropy calculation', function () {
        // Explicit profile without Shannon entropy strategy
        config()->set('redactor.default_profile', 'no_entropy_strategy_test');
        config()->set('redactor.profiles.no_entropy_strategy_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => false,
                'threshold' => 4.0,
                'min_length' => 25,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        // Should return 0.0 when no ShannonEntropyStrategy is found
        expect($redactor->calculateShannonEntropy('high-entropy-string-12345'))->toBe(0.0);
    });

    it('returns false when no ShannonEntropyStrategy is found during pattern checking', function () {
        // Explicit profile without Shannon entropy strategy
        config()->set('redactor.default_profile', 'no_pattern_strategy_test');
        config()->set('redactor.profiles.no_pattern_strategy_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\SafeKeysStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => false,
                'threshold' => 4.0,
                'min_length' => 25,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;
        $config = RedactorConfig::fromConfig();

        // Should return false when no ShannonEntropyStrategy is found
        expect($redactor->isCommonPattern('https://example.com', $config))->toBeFalse();
    });

    it('uses entropy caching for performance optimization', function () {
        // Explicit profile for caching test
        config()->set('redactor.default_profile', 'caching_test');
        config()->set('redactor.profiles.caching_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 4.0,
                'min_length' => 10,
                'exclusion_patterns' => [],
            ],
        ]);

        $redactor = new Redactor;

        $testString = 'sk-1234567890abcdef1234567890abcdef12345678';

        // Calculate entropy multiple times - should use caching
        $entropy1 = $redactor->calculateShannonEntropy($testString);
        $entropy2 = $redactor->calculateShannonEntropy($testString);
        $entropy3 = $redactor->calculateShannonEntropy($testString);

        // All calculations should return the same value
        expect($entropy1)->toBe($entropy2)
            ->and($entropy2)->toBe($entropy3)
            ->and($entropy1)->toBeGreaterThan(4.0); // Should be high entropy
    });

    it('handles cached entropy return path using direct strategy method calls', function () {
        // Test the cached entropy return path directly
        $strategy = new \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy;
        $config = new \Kirschbaum\Redactor\RedactorConfig(
            enabled: true,
            safeKeys: [],
            blockedKeys: [],
            patterns: [],
            replacement: '[REDACTED]',
            markRedacted: true,
            trackRedactedKeys: false,
            nonRedactableObjectBehavior: 'preserve',
            maxValueLength: null,
            redactLargeObjects: true,
            maxObjectSize: 100,
            shannonEntropy: [
                'enabled' => true,
                'threshold' => 3.0,
                'min_length' => 5,
                'exclusion_patterns' => [],
            ],
            strategies: [],
            profile: 'test'
        );
        $context = new \Kirschbaum\Redactor\RedactionContext($config);

        // Use reflection to directly call calculateShannonEntropy
        $reflection = new \ReflectionClass($strategy);
        $method = $reflection->getMethod('calculateShannonEntropy');
        $method->setAccessible(true);

        $testString = 'test string for entropy calculation';

        // First call calculates and caches
        $entropy1 = $method->invoke($strategy, $testString, $context);

        // Second call should hit cached path
        $entropy2 = $method->invoke($strategy, $testString, $context);

        expect($entropy1)->toBe($entropy2);
        expect($entropy1)->toBeFloat();
    });

    it('handles non-array exclusion patterns gracefully', function () {
        // Test when exclusion_patterns is not an array - this should hit line 103
        $strategy = new \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy;
        $config = new \Kirschbaum\Redactor\RedactorConfig(
            enabled: true,
            safeKeys: [],
            blockedKeys: [],
            patterns: [],
            replacement: '[REDACTED]',
            markRedacted: true,
            trackRedactedKeys: false,
            nonRedactableObjectBehavior: 'preserve',
            maxValueLength: null,
            redactLargeObjects: true,
            maxObjectSize: 100,
            shannonEntropy: [
                'enabled' => true,
                'threshold' => 2.0,
                'min_length' => 25,
                'exclusion_patterns' => 'not_an_array', // This should trigger line 103
            ],
            strategies: [],
            profile: 'test'
        );
        $context = new \Kirschbaum\Redactor\RedactionContext($config);

        // Use reflection to directly call isCommonPattern to hit line 103
        $reflection = new \ReflectionClass($strategy);
        $method = $reflection->getMethod('isCommonPattern');
        $method->setAccessible(true);

        $result = $method->invoke($strategy, 'test string that is long enough to be processed', $context);

        // Should return false when exclusion_patterns is not an array
        expect($result)->toBeFalse();
    });

    it('handles non-string patterns in exclusion patterns array', function () {
        // Test skipping non-string patterns in exclusion_patterns
        config()->set('redactor.profiles.mixed_exclusion_patterns', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 2.0,
                'min_length' => 5,
                'exclusion_patterns' => [
                    '/valid_pattern/',
                    123, // Non-string pattern - should be skipped
                    null, // Non-string pattern - should be skipped
                    '/another_valid/',
                ],
            ],
        ]);

        $redactor = new Redactor;
        $result = $redactor->redact(['test' => 'randomstring']);

        // Should process normally despite non-string patterns
        expect($result)->toBeArray();
    });

    it('handles long hex strings special case in isCommonPattern method', function () {
        // Test the special case for long hex strings that should still be redacted
        config()->set('redactor.profiles.hex_special_case', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy::class,
            ],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => [
                'enabled' => true,
                'threshold' => 2.0, // Low threshold to trigger redaction
                'min_length' => 25,
                'exclusion_patterns' => [
                    '/^[0-9a-f]+$/i', // Hex pattern - triggers special case check
                ],
            ],
        ]);

        $redactor = new Redactor;
        $result = $redactor->redact([
            'short_hex' => 'abc123', // Short hex - should not be redacted (below min_length)
            'long_hex_hash' => '1234567890abcdef1234567890abcdef12345678', // Long hex - should be redacted (special case)
            'normal_text' => 'short text', // Short text - below min_length
        ], 'hex_special_case');

        expect($result['short_hex'])->toBe('abc123') // Too short, not processed
            ->and($result['long_hex_hash'])->toBe('[REDACTED]') // Long hex triggers special case
            ->and($result['normal_text'])->toBe('short text') // Too short, not processed
            ->and($result['_redacted'])->toBeTrue();
    });
});
