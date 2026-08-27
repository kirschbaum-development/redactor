<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor;

use Illuminate\Support\Facades\Config;
use Kirschbaum\Redactor\Config\ConfigValue;
use Kirschbaum\Redactor\Support\Pcre;

readonly class RedactorConfig
{
    /** @var array<int, string> */
    public const OBJECT_BEHAVIORS = ['preserve', 'remove', 'empty_array', 'redact'];

    /**
     * How deep the redactor will walk before it stops and replaces the rest.
     *
     * Deep enough for any realistic log context; shallow enough that a cyclic
     * or pathologically nested payload cannot exhaust memory.
     */
    public const DEFAULT_MAX_DEPTH = 32;

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
        public int $maxDepth = self::DEFAULT_MAX_DEPTH,
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

        $shannonEntropy = ConfigValue::map($config['shannon_entropy'] ?? [], "profiles.{$profile}.shannon_entropy");

        // Coerce the entropy sub-keys here too: they are read on every string,
        // and env() hands them over as strings.
        if (array_key_exists('enabled', $shannonEntropy)) {
            $shannonEntropy['enabled'] = ConfigValue::bool($shannonEntropy['enabled'], true, "profiles.{$profile}.shannon_entropy.enabled");
        }

        if (array_key_exists('threshold', $shannonEntropy)) {
            $shannonEntropy['threshold'] = ConfigValue::float($shannonEntropy['threshold'], 4.8, "profiles.{$profile}.shannon_entropy.threshold");
        }

        if (array_key_exists('min_length', $shannonEntropy)) {
            $shannonEntropy['min_length'] = ConfigValue::positiveInt($shannonEntropy['min_length'], 25, "profiles.{$profile}.shannon_entropy.min_length");
        }

        return new self(
            enabled: ConfigValue::bool($config['enabled'] ?? true, true, "profiles.{$profile}.enabled"),
            safeKeys: array_map('strtolower', ConfigValue::stringList($config['safe_keys'] ?? [], "profiles.{$profile}.safe_keys")),
            blockedKeys: array_map('strtolower', ConfigValue::stringList($config['blocked_keys'] ?? [], "profiles.{$profile}.blocked_keys")),
            patterns: self::validatePatterns(ConfigValue::map($config['patterns'] ?? [], "profiles.{$profile}.patterns")),
            replacement: ConfigValue::string($config['replacement'] ?? '[REDACTED]', '[REDACTED]', "profiles.{$profile}.replacement"),
            markRedacted: ConfigValue::bool($config['mark_redacted'] ?? true, true, "profiles.{$profile}.mark_redacted"),
            trackRedactedKeys: ConfigValue::bool($config['track_redacted_keys'] ?? false, false, "profiles.{$profile}.track_redacted_keys"),
            nonRedactableObjectBehavior: ConfigValue::enum(
                $config['non_redactable_object_behavior'] ?? 'preserve',
                self::OBJECT_BEHAVIORS,
                'preserve',
                "profiles.{$profile}.non_redactable_object_behavior"
            ),
            maxValueLength: ConfigValue::positiveIntOrNull($config['max_value_length'] ?? null, null, "profiles.{$profile}.max_value_length"),
            redactLargeObjects: ConfigValue::bool($config['redact_large_objects'] ?? true, true, "profiles.{$profile}.redact_large_objects"),
            maxObjectSize: ConfigValue::positiveIntOrNull($config['max_object_size'] ?? 100, 100, "profiles.{$profile}.max_object_size"),
            shannonEntropy: $shannonEntropy,
            strategies: ConfigValue::map($config['strategies'] ?? [], "profiles.{$profile}.strategies"),
            profile: $profile,
            maxDepth: ConfigValue::positiveInt($config['max_depth'] ?? self::DEFAULT_MAX_DEPTH, self::DEFAULT_MAX_DEPTH, "profiles.{$profile}.max_depth"),
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
            if (Pcre::isValidPattern($pattern)) {
                $validPatterns[(string) $name] = $pattern;
            }
        }

        return $validPatterns;
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
