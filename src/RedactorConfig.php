<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor;

use Illuminate\Support\Facades\Config;

readonly class RedactorConfig
{
    public function __construct(
        public bool $enabled,
        /** @var array<string> */
        public array $safeKeys,
        /** @var array<string> */
        public array $blockedKeys,
        /** @var array<string, string> */
        public array $patterns,
        public string $replacement,
        public bool $markRedacted,
        public bool $trackRedactedKeys,
        public string $nonRedactableObjectBehavior,
        public ?int $maxValueLength,
        public bool $redactLargeObjects,
        public ?int $maxObjectSize,
        /** @var array<string, mixed> */
        public array $shannonEntropy,
        /** @var array<string, mixed> */
        public array $strategies,
        public string $profile,
    ) {}

    /**
     * Create a RedactorConfig instance from Laravel configuration.
     */
    public static function fromConfig(?string $profile = null): self
    {
        $defaultProfile = Config::get('redactor.default_profile', 'default');
        $profile = $profile ?? (is_string($defaultProfile) ? $defaultProfile : 'default');

        $profiles = Config::get('redactor.profiles', []);

        if (! is_array($profiles) || ! isset($profiles[$profile])) {
            throw new \InvalidArgumentException("Redaction profile '".$profile."' not found in configuration.");
        }

        $config = $profiles[$profile];

        if (! is_array($config)) {
            throw new \InvalidArgumentException("Invalid configuration for profile '".$profile."'.");
        }

        $safeKeys = $config['safe_keys'] ?? [];
        $blockedKeys = $config['blocked_keys'] ?? [];
        $patterns = $config['patterns'] ?? [];
        $shannonEntropy = $config['shannon_entropy'] ?? [];
        $strategies = $config['strategies'] ?? [];

        // Ensure proper array types for constructor
        /** @var array<string, mixed> $typedShannonEntropy */
        $typedShannonEntropy = is_array($shannonEntropy) ? $shannonEntropy : [];
        /** @var array<string, mixed> $typedStrategies */
        $typedStrategies = is_array($strategies) ? $strategies : [];

        return new self(
            enabled: is_bool($config['enabled'] ?? true) ? $config['enabled'] ?? true : true,
            safeKeys: is_array($safeKeys) ? array_map('strtolower', array_filter($safeKeys, 'is_string')) : [],
            blockedKeys: is_array($blockedKeys) ? array_map('strtolower', array_filter($blockedKeys, 'is_string')) : [],
            patterns: self::validatePatterns(is_array($patterns) ? $patterns : []),
            replacement: is_string($config['replacement'] ?? '[REDACTED]') ? $config['replacement'] ?? '[REDACTED]' : '[REDACTED]',
            markRedacted: is_bool($config['mark_redacted'] ?? true) ? $config['mark_redacted'] ?? true : true,
            trackRedactedKeys: is_bool($config['track_redacted_keys'] ?? false) ? $config['track_redacted_keys'] ?? false : false,
            nonRedactableObjectBehavior: is_string($config['non_redactable_object_behavior'] ?? 'preserve') ? $config['non_redactable_object_behavior'] ?? 'preserve' : 'preserve',
            maxValueLength: self::validateMaxValueLength($config['max_value_length'] ?? null),
            redactLargeObjects: is_bool($config['redact_large_objects'] ?? true) ? $config['redact_large_objects'] ?? true : true,
            maxObjectSize: is_int($config['max_object_size'] ?? 100) ? $config['max_object_size'] ?? 100 : 100,
            shannonEntropy: $typedShannonEntropy,
            strategies: $typedStrategies,
            profile: $profile,
        );
    }

    /**
     * Validate regex patterns and remove invalid ones.
     *
     * @param  array<mixed>  $patterns
     * @return array<string, string>
     */
    private static function validatePatterns(array $patterns): array
    {
        $validPatterns = [];

        foreach ($patterns as $name => $pattern) {
            if (! is_string($pattern)) {
                continue;
            }

            // Test if the regex pattern is valid
            if (@preg_match($pattern, '') !== false) {
                $validPatterns[(string) $name] = $pattern;
            }
        }

        return $validPatterns;
    }

    /**
     * Validate max value length configuration.
     */
    private static function validateMaxValueLength(mixed $value): ?int
    {
        if ($value === null) {
            return null;
        }

        if (is_numeric($value) && $value > 0) {
            return (int) $value;
        }

        return null;
    }

    /**
     * Get the list of available profiles.
     *
     * @return array<string>
     */
    public static function getAvailableProfiles(): array
    {
        $profiles = Config::get('redactor.profiles', []);

        return is_array($profiles) ? array_keys($profiles) : [];
    }

    /**
     * Check if a profile exists.
     */
    public static function profileExists(string $profile): bool
    {
        $profiles = Config::get('redactor.profiles', []);

        return is_array($profiles) && isset($profiles[$profile]);
    }
}
