<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor;

use Kirschbaum\Redactor\Config\ConfigValue;
use Kirschbaum\Redactor\Config\ProfileCache;
use Kirschbaum\Redactor\Exceptions\ConfigurationException;
use Kirschbaum\Redactor\Exceptions\ProfileNotFoundException;
use Kirschbaum\Redactor\Operators\OperatorRegistry;
use Kirschbaum\Redactor\Operators\OperatorSpec;
use Kirschbaum\Redactor\Operators\RedactionPolicy;
use Kirschbaum\Redactor\Path\PathTrie;
use Kirschbaum\Redactor\Patterns\PatternRule;
use Kirschbaum\Redactor\Support\AllowList;
use Kirschbaum\Redactor\Support\Configuration;
use Kirschbaum\Redactor\Support\KeyMatcher;
use Kirschbaum\Redactor\Support\SecretRegistry;

readonly class RedactorConfig
{
    /** @var array<int, string> */
    public const OBJECT_BEHAVIORS = ['preserve', 'remove', 'empty_array', 'redact'];

    /**
     * The behaviours for a string longer than max_value_length.
     *
     * The default, truncate, keeps the head, scans it and notes what was cut;
     * redact replaces the whole value.
     */
    public const LARGE_STRING_BEHAVIORS = ['truncate', 'redact'];

    /**
     * How deep the redactor will walk before it stops and replaces the rest.
     *
     * Deep enough for any realistic log context, shallow enough that a cyclic
     * or pathologically nested payload cannot exhaust memory.
     */
    public const DEFAULT_MAX_DEPTH = 32;

    /**
     * The compiled safe-key matcher.
     *
     * Held here rather than looked up per call: KeyMatcher memoises on the
     * pattern list, so finding the cached matcher meant imploding every key,
     * measured at 0.203us against 0.050us for the match it was avoiding.
     */
    public KeyMatcher $safeKeyMatcher;

    /** The compiled blocked-key matcher. See $safeKeyMatcher. */
    public KeyMatcher $blockedKeyMatcher;

    /**
     * The pattern rules ordered by min_length, each paired with its declared position.
     *
     * Lets the regex strategy stop at the first rule too long to match the
     * subject. Declared order still decides an equal-score overlap, through
     * the priority on each detection.
     *
     * @var array<int, array{0: PatternRule, 1: int}>
     */
    public array $patternsByLength;

    /**
     * A short digest of everything that decides what this profile detects.
     *
     * Two scans with the same fingerprint used the same rules, so a baseline
     * that records its fingerprint makes a rules change visible rather than
     * silently reinterpreting what "accepted" meant.
     */
    public string $rulesetFingerprint;

    /**
     * A number unique to this built profile, changing on every rebuild.
     *
     * Anything cached against a profile can key on it and be sure a rebuilt
     * profile is never served a stale derivative.
     */
    public int $buildId;

    /**
     * The values that are never redacted, whichever detector reports them.
     *
     * Checked after detection rather than instead of it, so the rules stay as
     * strong as they were written.
     */
    public AllowList $allowlist;

    public function __construct(
        public bool $enabled,
        /** @var array<int, string> */
        public array $safeKeys,
        /** @var array<int, string> */
        public array $blockedKeys,
        /** @var array<string, PatternRule> */
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
        /** The score below which detections are not acted on. */
        public float $minConfidence = 0.0,
        public RedactionPolicy $policy = new RedactionPolicy,
        /** @var array<string, mixed> */
        public array $pseudonymization = [],
        /** The path rules, compiled once per profile and consulted before any strategy runs. */
        public PathTrie $paths = new PathTrie,
        public string $largeStringBehavior = 'truncate',
        ?AllowList $allowlist = null,
        /** The application's own credentials, redacted wherever they appear verbatim. */
        public SecretRegistry $knownSecrets = new SecretRegistry,
        /** @var array<string, mixed> The named entity recognition settings. */
        public array $recognition = [],
    ) {
        $this->safeKeyMatcher = KeyMatcher::for($this->safeKeys);
        $this->blockedKeyMatcher = KeyMatcher::for($this->blockedKeys);
        $this->allowlist = $allowlist ?? AllowList::none();
        $this->buildId = ProfileCache::nextBuildId();
        $this->rulesetFingerprint = $this->fingerprint($this->patterns, $this->shannonEntropy, $this->minConfidence, $this->safeKeys, $this->blockedKeys);

        $ordered = [];
        $position = 0;

        foreach ($this->patterns as $rule) {
            $ordered[] = [$rule, $position++];
        }

        usort($ordered, fn (array $a, array $b): int => $a[0]->minLength <=> $b[0]->minLength ?: $a[1] <=> $b[1]);

        $this->patternsByLength = $ordered;
    }

    /**
     * Create a new RedactorConfig instance from the application's configuration.
     */
    public static function fromConfig(?string $profile = null): self
    {
        $defaultProfile = Configuration::get('redactor.default_profile', 'default');
        $profile ??= is_string($defaultProfile) ? $defaultProfile : 'default';

        $profiles = Configuration::get('redactor.profiles', []);

        if (! is_array($profiles) || ! isset($profiles[$profile])) {
            throw ProfileNotFoundException::named($profile);
        }

        $config = $profiles[$profile];

        if (! is_array($config)) {
            throw new ConfigurationException("Redaction profile [{$profile}] must be an array.");
        }

        // Settings folded in from outside the profile must rebuild it when they
        // change, or a rotated salt would keep old and new logs joinable and a
        // rotated APP_KEY would go unredacted; validation happens once below...
        $shared = [Configuration::get('redactor.pseudonymization'), self::knownSecretSources($config['known_secrets'] ?? [])];

        $cached = ProfileCache::get($profile, $config, $shared);

        if ($cached instanceof RedactorConfig) {
            return $cached;
        }

        $shannonEntropy = ConfigValue::map($config['shannon_entropy'] ?? [], "profiles.{$profile}.shannon_entropy");

        // The entropy sub-keys are read on every string and env() hands them over as strings...
        if (array_key_exists('enabled', $shannonEntropy)) {
            $shannonEntropy['enabled'] = ConfigValue::bool($shannonEntropy['enabled'], true, "profiles.{$profile}.shannon_entropy.enabled");
        }

        if (array_key_exists('threshold', $shannonEntropy)) {
            $shannonEntropy['threshold'] = ConfigValue::float($shannonEntropy['threshold'], 4.8, "profiles.{$profile}.shannon_entropy.threshold");
        }

        if (array_key_exists('min_length', $shannonEntropy)) {
            $shannonEntropy['min_length'] = ConfigValue::positiveInt($shannonEntropy['min_length'], 25, "profiles.{$profile}.shannon_entropy.min_length");
        }

        $built = new self(
            enabled: ConfigValue::bool($config['enabled'] ?? true, true, "profiles.{$profile}.enabled"),
            safeKeys: array_map(strtolower(...), ConfigValue::stringList($config['safe_keys'] ?? [], "profiles.{$profile}.safe_keys")),
            blockedKeys: array_map(strtolower(...), ConfigValue::stringList($config['blocked_keys'] ?? [], "profiles.{$profile}.blocked_keys")),
            patterns: self::buildPatternRules(ConfigValue::map($config['patterns'] ?? [], "profiles.{$profile}.patterns"), $profile),
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
            minConfidence: self::confidenceFloor($config['min_confidence'] ?? 0.0, "profiles.{$profile}.min_confidence"),
            policy: self::buildPolicy($config['operators'] ?? [], $profile),
            pseudonymization: self::pseudonymizationSettings($config['pseudonymization'] ?? [], $profile),
            paths: self::buildPaths($config['paths'] ?? [], $profile),
            largeStringBehavior: ConfigValue::enum(
                $config['large_string_behavior'] ?? 'truncate',
                self::LARGE_STRING_BEHAVIORS,
                'truncate',
                "profiles.{$profile}.large_string_behavior"
            ),
            allowlist: AllowList::for(ConfigValue::stringList($config['allowlist'] ?? [], "profiles.{$profile}.allowlist")),
            knownSecrets: self::buildKnownSecrets($config['known_secrets'] ?? [], $profile),
            recognition: self::recognitionSettings($config['recognition'] ?? [], $profile),
        );

        return ProfileCache::put($profile, $config, $built, $shared);
    }

    /**
     * Get a digest of the settings that decide what the profile detects.
     *
     * @param  array<string, PatternRule>  $patterns
     * @param  array<string, mixed>  $entropy
     * @param  array<int, string>  $safeKeys
     * @param  array<int, string>  $blockedKeys
     */
    private function fingerprint(array $patterns, array $entropy, float $minConfidence, array $safeKeys, array $blockedKeys): string
    {
        $rules = [];

        foreach ($patterns as $name => $rule) {
            $rules[$name] = [
                $rule->pattern, $rule->capture, $rule->validator, $rule->entity(), $rule->confidence,
                $rule->mode, $rule->keep, $rule->keywords, $rule->minLength,
                $rule->operator?->name, $rule->operator?->options,
            ];
        }

        $encoded = json_encode([$rules, $entropy, $minConfidence, $safeKeys, $blockedKeys]);

        return substr(hash('sha256', $encoded === false ? serialize($rules) : $encoded), 0, 16);
    }

    /**
     * Validate the shape of the recognition settings.
     *
     * @return array<string, mixed>
     */
    private static function recognitionSettings(mixed $settings, string $profile): array
    {
        $map = ConfigValue::map($settings, "profiles.{$profile}.recognition");

        if (array_key_exists('enabled', $map)) {
            $map['enabled'] = ConfigValue::bool($map['enabled'], false, "profiles.{$profile}.recognition.enabled");
        }

        foreach (['min_length', 'max_length', 'min_words', 'failure_threshold', 'cooldown'] as $key) {
            if (array_key_exists($key, $map)) {
                $map[$key] = ConfigValue::positiveInt($map[$key], 1, "profiles.{$profile}.recognition.{$key}");
            }
        }

        foreach (['score_threshold', 'timeout'] as $key) {
            if (array_key_exists($key, $map)) {
                $map[$key] = ConfigValue::float($map[$key], 0.0, "profiles.{$profile}.recognition.{$key}");
            }
        }

        return $map;
    }

    /**
     * Collect the profile's known secrets from literal values and config keys.
     *
     * A config key may point at an array, in which case every string leaf
     * under it is registered. Non-string leaves and values too short to be
     * safe are skipped silently, since a null secret in a local environment
     * must not fail the profile.
     */
    private static function buildKnownSecrets(mixed $settings, string $profile): SecretRegistry
    {
        $map = ConfigValue::map($settings, "profiles.{$profile}.known_secrets");

        $registry = new SecretRegistry;

        foreach (ConfigValue::stringList($map['values'] ?? [], "profiles.{$profile}.known_secrets.values") as $value) {
            $registry->add($value);
        }

        foreach (ConfigValue::stringList($map['config'] ?? [], "profiles.{$profile}.known_secrets.config") as $key) {
            self::registerLeaves($registry, Configuration::get($key));
        }

        return $registry;
    }

    /**
     * Get the current values behind the profile's known-secret config keys.
     *
     * Lets the cache tell when one of them changes.
     *
     * @return array<string, mixed>
     */
    private static function knownSecretSources(mixed $settings): array
    {
        if (! is_array($settings) || ! isset($settings['config']) || ! is_array($settings['config'])) {
            return [];
        }

        $sources = [];

        foreach ($settings['config'] as $key) {
            if (is_string($key)) {
                $sources[$key] = Configuration::get($key);
            }
        }

        return $sources;
    }

    /**
     * Register every string leaf under the value as a known secret.
     */
    private static function registerLeaves(SecretRegistry $registry, mixed $value): void
    {
        if (is_string($value)) {
            $registry->add($value);

            return;
        }

        if (is_array($value)) {
            foreach ($value as $leaf) {
                self::registerLeaves($registry, $leaf);
            }
        }
    }

    /**
     * Merge the global pseudonymization settings with any profile override.
     *
     * The key is almost always global so surrogates correlate across every
     * profile, while a profile may still set its own salt to break
     * correlation deliberately, or switch the feature off.
     *
     * @return array<string, mixed>
     */
    private static function pseudonymizationSettings(mixed $profileSettings, string $profile): array
    {
        $global = ConfigValue::map(Configuration::get('redactor.pseudonymization', []), 'pseudonymization');
        $local = ConfigValue::map($profileSettings, "profiles.{$profile}.pseudonymization");

        return [...$global, ...array_filter($local, fn ($v): bool => $v !== null)];
    }

    /**
     * Compile the profile's path rules.
     */
    private static function buildPaths(mixed $paths, string $profile): PathTrie
    {
        $map = ConfigValue::map($paths, "profiles.{$profile}.paths");

        $rules = [];

        foreach ($map as $pattern => $definition) {
            $rules[(string) $pattern] = OperatorSpec::parse($definition, "profiles.{$profile}.paths.{$pattern}");
        }

        return PathTrie::compile($rules);
    }

    /**
     * Validate the profile's confidence floor.
     */
    private static function confidenceFloor(mixed $value, string $path): float
    {
        $floor = ConfigValue::float($value, 0.0, $path);

        if ($floor < 0.0 || $floor > 1.0) {
            throw new ConfigurationException(sprintf(
                'Redactor config [%s] must be between 0 and 1, got %s.',
                $path,
                (string) $floor
            ));
        }

        return $floor;
    }

    /**
     * Build the per-entity operator policy for a profile.
     *
     * @param  mixed  $operators
     */
    private static function buildPolicy($operators, string $profile): RedactionPolicy
    {
        $map = ConfigValue::map($operators, "profiles.{$profile}.operators");

        $specs = [];

        foreach ($map as $entity => $definition) {
            $specs[$entity] = OperatorSpec::parse($definition, "profiles.{$profile}.operators.{$entity}");
        }

        return new RedactionPolicy(
            $specs,
            $specs['default'] ?? new OperatorSpec(OperatorRegistry::REDACT),
        );
    }

    /**
     * Turn the configured patterns into rules, dropping uncompilable ones.
     *
     * @param  array<string, mixed>  $patterns
     * @return array<string, PatternRule>
     */
    private static function buildPatternRules(array $patterns, string $profile): array
    {
        $rules = [];

        foreach ($patterns as $name => $definition) {
            $rule = PatternRule::fromConfig(
                (string) $name,
                $definition,
                "profiles.{$profile}.patterns.{$name}"
            );

            if ($rule instanceof PatternRule) {
                $rules[(string) $name] = $rule;
            }
        }

        return $rules;
    }

    /**
     * Get the names of the configured profiles.
     *
     * @return array<string>
     */
    public static function profiles(): array
    {
        $profiles = Configuration::get('redactor.profiles', []);

        return is_array($profiles) ? array_keys($profiles) : [];
    }

    /**
     * Determine if a profile is configured.
     */
    public static function hasProfile(string $profile): bool
    {
        $profiles = Configuration::get('redactor.profiles', []);

        return is_array($profiles) && isset($profiles[$profile]);
    }
}
