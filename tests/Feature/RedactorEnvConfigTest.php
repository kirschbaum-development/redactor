<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Config\ConfigValue;
use Kirschbaum\Redactor\Exceptions\ConfigurationException;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Scanner\FileCollector;
use Kirschbaum\Redactor\Strategies\LargeObjectStrategy;

/**
 * Laravel's env() only casts "true", "false", "null" and "empty". Every numeric
 * or textual environment variable therefore reaches config as a string, so each
 * documented REDACTOR_* variable must survive that form.
 */
describe('Documented environment variables', function (): void {
    /**
     * Mirrors config/redactor.php with every value as the string env() produces.
     */
    function envShapedProfile(array $overrides = []): array
    {
        return array_merge([
            'enabled' => 'true',
            'strategies' => [LargeObjectStrategy::class],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => [],
            'replacement' => '[MASKED]',
            'mark_redacted' => 'false',
            'track_redacted_keys' => 'true',
            'non_redactable_object_behavior' => 'redact',
            'max_value_length' => '2500',
            'redact_large_objects' => 'true',
            'max_object_size' => '25',
            'shannon_entropy' => [
                'enabled' => 'true',
                'threshold' => '4.2',
                'min_length' => '18',
                'exclusion_patterns' => [],
            ],
        ], $overrides);
    }

    it('applies every profile value when it arrives as a string', function (): void {
        config()->set('redactor.profiles.env_shaped', envShapedProfile());

        $config = RedactorConfig::fromConfig('env_shaped');

        expect($config->enabled)->toBeTrue()
            ->and($config->replacement)->toBe('[MASKED]')
            ->and($config->markRedacted)->toBeFalse()
            ->and($config->trackRedactedKeys)->toBeTrue()
            ->and($config->nonRedactableObjectBehavior)->toBe('redact')
            ->and($config->maxValueLength)->toBe(2500)
            ->and($config->redactLargeObjects)->toBeTrue()
            ->and($config->maxObjectSize)->toBe(25)
            ->and($config->shannonEntropy['enabled'])->toBeTrue()
            ->and($config->shannonEntropy['threshold'])->toBe(4.2)
            ->and($config->shannonEntropy['min_length'])->toBe(18);
    });

    it('honours REDACTOR_MAX_OBJECT_SIZE end to end', function (): void {
        // is_int() rejected the string form, so this knob always fell back to
        // 100 and arrays of 26-100 items were never redacted.
        config()->set('redactor.profiles.env_shaped', envShapedProfile([
            'mark_redacted' => 'true',
        ]));

        $payload = array_fill_keys(
            array_map(fn (int $i): string => "field_{$i}", range(1, 30)),
            'value'
        );

        $result = resolve(Redactor::class)->redact($payload, 'env_shaped');

        expect($result)->toHaveKey('_large_object_redacted');
    });

    it('honours REDACTOR_ENABLED=false as a string', function (): void {
        config()->set('redactor.profiles.env_disabled', envShapedProfile(['enabled' => 'false']));

        expect(RedactorConfig::fromConfig('env_disabled')->enabled)->toBeFalse();
    });

    it('accepts the scan max file size as a string', function (): void {
        // Config::integer() threw on this, so setting the documented
        // REDACTOR_SCAN_MAX_FILE_SIZE made redactor:scan fail outright.
        config()->set('redactor.scan.max_file_size', '1024');

        $size = ConfigValue::positiveInt(
            config('redactor.scan.max_file_size'),
            10_485_760,
            'scan.max_file_size'
        );

        expect($size)->toBe(1024);

        $dir = sys_get_temp_dir().'/redactor_env_'.uniqid();
        mkdir($dir);
        file_put_contents($dir.'/small.txt', str_repeat('a', 10));
        file_put_contents($dir.'/big.txt', str_repeat('a', 2048));

        $files = FileCollector::collect([$dir], [], $size);

        expect($files)->toHaveCount(1)
            ->and(basename($files[0]))->toBe('small.txt');

        cleanupDirectory($dir);
    });

    it('rejects an unknown non_redactable_object_behavior rather than ignoring it', function (): void {
        config()->set('redactor.profiles.env_bad_behavior', envShapedProfile([
            'non_redactable_object_behavior' => 'delete_everything',
        ]));

        expect(fn (): RedactorConfig => RedactorConfig::fromConfig('env_bad_behavior'))
            ->toThrow(\InvalidArgumentException::class, 'non_redactable_object_behavior');
    });

    it('rejects a non-numeric entropy threshold', function (): void {
        config()->set('redactor.profiles.env_bad_threshold', envShapedProfile([
            'shannon_entropy' => ['enabled' => 'true', 'threshold' => 'high'],
        ]));

        expect(fn (): RedactorConfig => RedactorConfig::fromConfig('env_bad_threshold'))
            ->toThrow(\InvalidArgumentException::class, 'shannon_entropy.threshold');
    });
});

describe('ConfigValue coercion', function (): void {
    it('accepts the truthy and falsy spellings env files use', function (): void {
        foreach (['true', 'TRUE', '1', 'yes', 'on', true, 1] as $truthy) {
            expect(ConfigValue::bool($truthy, false, 'p'))->toBeTrue();
        }

        foreach (['false', 'FALSE', '0', 'no', 'off', '', false, 0] as $falsy) {
            expect(ConfigValue::bool($falsy, true, 'p'))->toBeFalse();
        }
    });

    it('rejects strings that only look numeric', function (): void {
        expect(fn (): int => ConfigValue::positiveInt('12abc', 1, 'p'))
            ->toThrow(\InvalidArgumentException::class)
            ->and(fn (): int => ConfigValue::positiveInt('1.5', 1, 'p'))
            ->toThrow(\InvalidArgumentException::class);
    });

    it('falls back to the default when the value is absent', function (): void {
        expect(ConfigValue::bool(null, true, 'p'))->toBeTrue()
            ->and(ConfigValue::string(null, 'x', 'p'))->toBe('x')
            ->and(ConfigValue::positiveInt(null, 7, 'p'))->toBe(7)
            ->and(ConfigValue::float(null, 1.5, 'p'))->toBe(1.5)
            ->and(ConfigValue::stringList(null, 'p'))->toBe([]);
    });

    it('drops non-string entries from string lists', function (): void {
        expect(ConfigValue::stringList(['a', 1, null, 'b', []], 'p'))->toBe(['a', 'b']);
    });

    it('names the offending config path in every message', function (): void {
        expect(fn (): bool => ConfigValue::bool('maybe', true, 'profiles.x.enabled'))
            ->toThrow(\InvalidArgumentException::class, 'profiles.x.enabled');
    });
});

describe('ConfigValue coercion of the other shapes', function (): void {
    it('stringifies a number, since a replacement of 0 is still a replacement', function (): void {
        expect(ConfigValue::string(5, 'x', 'p'))->toBe('5')
            ->and(ConfigValue::string(1.5, 'x', 'p'))->toBe('1.5');
    });

    it('rejects anything else as a string and says what it got', function (): void {
        expect(fn (): string => ConfigValue::string(true, 'x', 'p'))
            ->toThrow(ConfigurationException::class, 'got true')
            ->and(fn (): string => ConfigValue::string(['a'], 'x', 'p'))
            ->toThrow(ConfigurationException::class, 'got array')
            ->and(fn (): string => ConfigValue::string(new \stdClass, 'x', 'p'))
            ->toThrow(ConfigurationException::class, 'got stdClass');
    });

    it('describes a scalar of the wrong kind with its type', function (): void {
        expect(fn (): bool => ConfigValue::bool(2, true, 'p'))
            ->toThrow(ConfigurationException::class, 'got integer(2)')
            ->and(fn (): bool => ConfigValue::bool(1.5, true, 'p'))
            ->toThrow(ConfigurationException::class, 'got double(1.5)')
            ->and(fn (): array => ConfigValue::map('nope', 'p'))
            ->toThrow(ConfigurationException::class, 'got string("nope")');
    });

    it('reads a missing map as empty and a whole-number float as an integer', function (): void {
        expect(ConfigValue::map(null, 'p'))->toBe([])
            ->and(ConfigValue::positiveInt(3.0, 1, 'p'))->toBe(3);
    });
});
