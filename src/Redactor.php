<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor;

use Illuminate\Support\Facades\Config;
use Kirschbaum\Redactor\Strategies\Contracts\ChainableStrategy;
use Kirschbaum\Redactor\Strategies\RedactionStrategyInterface;
use Kirschbaum\Redactor\Strategies\StrategyOutcome;
use Kirschbaum\Redactor\Support\InternalLog;

class Redactor
{
    /** @var array<string, array<RedactionStrategyInterface>> */
    private array $profileStrategies = [];

    /** @var array<string, RedactionStrategyInterface> */
    private array $customStrategies = [];

    private bool $customStrategiesLoaded = false;

    /**
     * Redact sensitive data from content using strategy pattern.
     *
     * @param  mixed  $content  The content to redact
     * @param  string|null  $profile  The redaction profile to use (defaults to config default)
     */
    public function redact(mixed $content, ?string $profile = null): mixed
    {
        $config = RedactorConfig::fromConfig($profile);

        if (! $config->enabled) {
            return $content;
        }

        $context = new RedactionContext($config);
        $strategies = $this->getStrategiesForProfile($config);

        $redactedContent = $this->redactRecursively($content, '', $context, $strategies);

        // Only add metadata to array results
        if (is_array($redactedContent) && $context->hasRedactions() && $config->markRedacted) {
            $redactedContent['_redacted'] = true;

            if ($config->trackRedactedKeys && ! empty($context->getRedactedKeys())) {
                $redactedContent['_redacted_keys'] = $context->getRedactedKeys();
            }
        }

        return $redactedContent;
    }

    /**
     * Redact content without ever throwing.
     *
     * Intended for the logging pipeline, where an exception - a profile name
     * typo, an unreadable config value, a strategy that blows up on unexpected
     * input - would take down logging for the whole channel, including the
     * error that would have explained why.
     *
     * On failure the content is replaced wholesale rather than passed through:
     * if redaction could not be verified, the data is not safe to emit.
     */
    public function redactSafely(mixed $content, ?string $profile = null): mixed
    {
        try {
            return $this->redact($content, $profile);
        } catch (\Throwable $e) {
            InternalLog::warning('Redaction failed; content replaced as a precaution', [
                'profile' => $profile,
                'exception_type' => get_class($e),
                'exception_message' => $e->getMessage(),
            ]);

            return $this->failClosed($profile);
        }
    }

    /**
     * The value emitted when redaction could not be completed.
     */
    protected function failClosed(?string $profile): string
    {
        $replacement = '[REDACTED]';

        try {
            $replacement = RedactorConfig::fromConfig($profile)->replacement;
        } catch (\Throwable) {
            // The config is what failed; fall back to the documented default.
        }

        return $replacement.' (redaction failed)';
    }

    /**
     * Resolve every configured profile, collecting the problems found.
     *
     * Run this at deploy time (see the redactor:validate command) so a bad
     * profile fails the deploy rather than the first log line that uses it.
     *
     * @return array<string, string> profile name => error message
     */
    public function validateProfiles(): array
    {
        $errors = [];

        foreach (RedactorConfig::getAvailableProfiles() as $profile) {
            try {
                $config = RedactorConfig::fromConfig($profile);

                $strategies = $this->buildStrategiesForProfile($config);

                $configured = array_values(array_filter($config->strategies, 'is_string'));

                if (count($strategies) !== count($configured)) {
                    $resolved = array_map(fn ($s) => get_class($s), $strategies);

                    $unresolved = array_values(array_filter(
                        $configured,
                        fn (string $name) => ! in_array($name, $resolved, true)
                            && ! isset($this->customStrategies[$name])
                    ));

                    $errors[$profile] = 'Unresolvable strategies: '.implode(', ', $unresolved);
                }
            } catch (\Throwable $e) {
                $errors[$profile] = $e->getMessage();
            }
        }

        return $errors;
    }

    /**
     * Get strategies for a specific profile.
     *
     * @return array<RedactionStrategyInterface>
     */
    private function getStrategiesForProfile(RedactorConfig $config): array
    {
        // The redactor is a singleton, so the cache outlives any one call and
        // must not go stale when a profile's strategy list changes underneath
        // it. Keying on the resolved class list makes that impossible.
        $cacheKey = $config->profile.'|'.implode(',', array_filter($config->strategies, 'is_string'));

        if (! isset($this->profileStrategies[$cacheKey])) {
            $this->profileStrategies[$cacheKey] = $this->buildStrategiesForProfile($config);
        }

        return $this->profileStrategies[$cacheKey];
    }

    /**
     * Build strategies for a profile based on configuration.
     *
     * @return array<RedactionStrategyInterface>
     */
    private function buildStrategiesForProfile(RedactorConfig $config): array
    {
        $strategies = [];
        $strategyClasses = $config->strategies;

        // Build strategy instances based on config ordering (array order = priority)
        foreach ($strategyClasses as $strategyClass) {
            if (! is_string($strategyClass)) {
                continue;
            }
            $strategy = $this->createStrategyInstance($strategyClass, $config);

            if ($strategy !== null) {
                $strategies[] = $strategy;
            }
        }

        return $strategies;
    }

    /**
     * Create a strategy instance by class string.
     */
    private function createStrategyInstance(string $strategyClass, RedactorConfig $config): ?RedactionStrategyInterface
    {
        $this->loadCustomStrategies();

        // Check for custom strategies first (backward compatibility with name => class mapping)
        if (isset($this->customStrategies[$strategyClass])) {
            return clone $this->customStrategies[$strategyClass];
        }

        // Create strategy instance from class string
        if (class_exists($strategyClass) && is_subclass_of($strategyClass, RedactionStrategyInterface::class)) {
            return new $strategyClass;
        }

        return null;
    }

    /**
     * Load custom strategies from configuration.
     */
    private function loadCustomStrategies(): void
    {
        // Loaded lazily rather than in the constructor: as a singleton the
        // redactor is often built before the config it depends on is final.
        if ($this->customStrategiesLoaded) {
            return;
        }

        $this->customStrategiesLoaded = true;

        $customStrategyClasses = Config::get('redactor.custom_strategies', []);

        if (! is_array($customStrategyClasses)) {
            return;
        }

        foreach ($customStrategyClasses as $name => $className) {
            if (is_string($className) && is_string($name) && class_exists($className) && is_subclass_of($className, RedactionStrategyInterface::class)) {
                $this->customStrategies[$name] = new $className;
            }
        }
    }

    /**
     * Recursively redact data using strategies.
     *
     * @param  array<RedactionStrategyInterface>  $strategies
     */
    protected function redactRecursively(mixed $data, string $key, RedactionContext $context, array $strategies): mixed
    {
        if (! is_array($data) && ! is_object($data)) {
            // Apply strategies to scalar values
            return $this->applyStrategiesToValue($data, $key, $context, $strategies);
        }

        // Nothing below here may recurse without a depth budget: a self-
        // referencing toArray() or a pathologically nested payload would
        // otherwise run until PHP exhausts its memory limit and dies.
        if (! $context->enterDepth()) {
            return $this->markDepthExceeded($context);
        }

        try {
            if (is_array($data)) {
                /** @var array<string, mixed> $arrayData */
                $arrayData = $data;

                return $this->redactArray($arrayData, $context, $strategies);
            }

            return $this->redactObject($data, $key, $context, $strategies);
        } finally {
            $context->leaveDepth();
        }
    }

    /**
     * Replace a subtree that sits deeper than the configured max depth.
     */
    protected function markDepthExceeded(RedactionContext $context): string
    {
        $context->markRedacted();

        return sprintf(
            '%s (Max depth of %d exceeded)',
            $context->config->replacement,
            $context->config->maxDepth
        );
    }

    /**
     * Redact sensitive data from an array.
     *
     * @param  array<string, mixed>  $array
     * @param  array<RedactionStrategyInterface>  $strategies
     * @return array<string, mixed>
     */
    protected function redactArray(array $array, RedactionContext $context, array $strategies): array
    {
        // Check for large arrays first (applies to the whole array)
        $outcome = $this->applyStrategies($array, '', $context, $strategies);
        if ($outcome !== null && $outcome->value !== $array) {
            // Array was redacted by a strategy (e.g., LargeObjectStrategy)
            if (is_array($outcome->value)) {
                /** @var array<string, mixed> $typedArray */
                $typedArray = $outcome->value;

                return $typedArray;
            }

            return ['_redacted_array' => $outcome->value];
        }

        /** @var array<string, mixed> $result */
        $result = [];

        foreach ($array as $key => $value) {
            $keyString = (string) $key;

            // Apply strategies to the key-value pair
            $outcome = $this->applyStrategies($value, $keyString, $context, $strategies);
            $processedValue = $outcome !== null ? $outcome->value : $value;

            // Handle object removal case
            if ($processedValue === '__REDACTOR_REMOVE_OBJECT__') {
                continue; // Skip adding this key to the result
            }

            // No strategy claimed this container, so walk into it.
            if ($outcome === null && (is_array($value) || is_object($value))) {
                $processedValue = $this->redactRecursively($value, $keyString, $context, $strategies);

                // Handle object removal case after recursive processing
                if ($processedValue === '__REDACTOR_REMOVE_OBJECT__') {
                    continue; // Skip adding this key to the result
                }
            }

            $result[(string) $key] = $processedValue;
        }

        return $result;
    }

    /**
     * Redact sensitive data from an object.
     *
     * @param  array<RedactionStrategyInterface>  $strategies
     */
    protected function redactObject(object $object, string $key, RedactionContext $context, array $strategies): mixed
    {
        // First, check if the object itself should be redacted by strategies
        $outcome = $this->applyStrategies($object, $key, $context, $strategies);
        if ($outcome !== null && $outcome->value !== $object) {
            return $outcome->value;
        }

        // An object already on the stack means following it again would loop.
        // json_encode() catches this for itself, but the toArray() path below
        // is tried first and has no such protection.
        if (! $context->enterObject($object)) {
            $context->markRedacted();

            return sprintf(
                '%s (Circular reference to %s)',
                $context->config->replacement,
                get_class($object)
            );
        }

        try {
            return $this->redactObjectContents($object, $context, $strategies);
        } finally {
            $context->leaveObject($object);
        }
    }

    /**
     * Convert an object to an array and redact it.
     *
     * @param  array<RedactionStrategyInterface>  $strategies
     */
    protected function redactObjectContents(object $object, RedactionContext $context, array $strategies): mixed
    {
        // Try to convert object to array using toArray() method if available
        if (method_exists($object, 'toArray')) {
            try {
                /** @var array<string, mixed> $array */
                $array = $object->toArray();

                return $this->redactArray($array, $context, $strategies);
            } catch (\Throwable) {
                // Fall through to other methods
            }
        }

        // Try JSON encoding first to detect circular references and other issues
        try {
            $jsonString = json_encode($object, JSON_THROW_ON_ERROR);
            $array = json_decode($jsonString, true, 512, JSON_THROW_ON_ERROR);

            if (! is_array($array)) {
                InternalLog::warning('Unable to redact object - JSON decode did not return array', [
                    'object_class' => get_class($object),
                    'reason' => 'json_decode_not_array',
                    'decoded_type' => gettype($array),
                    'behavior' => $context->config->nonRedactableObjectBehavior,
                ]);

                return $this->handleNonRedactableObject($object, $context);
            }

            /** @var array<string, mixed> $arrayData */
            $arrayData = $array;

            return $this->redactArray($arrayData, $context, $strategies);

        } catch (\Throwable $e) {
            InternalLog::warning('Exception while trying to redact object', [
                'object_class' => get_class($object),
                'reason' => 'exception_during_processing',
                'exception_type' => get_class($e),
                'exception_message' => $e->getMessage(),
                'behavior' => $context->config->nonRedactableObjectBehavior,
            ]);

            return $this->handleNonRedactableObject($object, $context);
        }
    }

    /**
     * Apply strategies to a value in priority order.
     *
     * @param  array<RedactionStrategyInterface>  $strategies
     */
    protected function applyStrategies(mixed $value, string $key, RedactionContext $context, array $strategies): ?StrategyOutcome
    {
        $handled = false;

        foreach ($strategies as $strategy) {
            if (! $strategy->shouldHandle($value, $key, $context)) {
                continue;
            }

            $value = $strategy->handle($value, $key, $context);
            $handled = true;

            // A strategy that replaces the value wholesale ends the chain.
            // A chainable one only rewrote part of a string, so the remaining
            // strategies still need to inspect what is left standing.
            if (! $strategy instanceof ChainableStrategy) {
                return new StrategyOutcome($value);
            }
        }

        return $handled ? new StrategyOutcome($value) : null;
    }

    /**
     * Run the strategy chain, returning the value unchanged if none applied.
     *
     * @param  array<RedactionStrategyInterface>  $strategies
     */
    protected function applyStrategiesToValue(mixed $value, string $key, RedactionContext $context, array $strategies): mixed
    {
        $outcome = $this->applyStrategies($value, $key, $context, $strategies);

        return $outcome !== null ? $outcome->value : $value;
    }

    /**
     * Handle objects that cannot be redacted based on configuration.
     */
    protected function handleNonRedactableObject(object $object, RedactionContext $context): mixed
    {
        return match ($context->config->nonRedactableObjectBehavior) {
            'remove' => $this->removeObject($context),
            'empty_array' => $this->replaceWithEmptyArray($context),
            'redact' => $this->replaceWithRedactionText($object, $context),
            default => $object, // 'preserve' or any unknown value
        };
    }

    /**
     * Remove the object entirely (return a special marker that can be filtered out).
     */
    protected function removeObject(RedactionContext $context): string
    {
        $context->markRedacted();

        return '__REDACTOR_REMOVE_OBJECT__';
    }

    /** @return array<string, mixed> */
    protected function replaceWithEmptyArray(RedactionContext $context): array
    {
        $context->markRedacted();

        return [];
    }

    /**
     * Replace with redaction text.
     */
    protected function replaceWithRedactionText(object $object, RedactionContext $context): string
    {
        $context->markRedacted();

        return sprintf('%s (Non-redactable object %s)', $context->config->replacement, get_class($object));
    }

    /**
     * Register a custom strategy for use in profiles.
     */
    public function registerCustomStrategy(string $name, RedactionStrategyInterface $strategy): void
    {
        $this->loadCustomStrategies();

        $this->customStrategies[$name] = $strategy;

        // Clear cached profile strategies since we've added a new strategy
        $this->profileStrategies = [];
    }

    /**
     * Get available redaction profiles.
     *
     * @return array<string>
     */
    public function getAvailableProfiles(): array
    {
        /** @var array<string> $profiles */
        $profiles = RedactorConfig::getAvailableProfiles();

        return $profiles;
    }

    /**
     * Check if a profile exists.
     */
    public function profileExists(string $profile): bool
    {
        return RedactorConfig::profileExists($profile);
    }

    /**
     * Get all strategies for a specific profile (for testing/debugging).
     *
     * @return array<RedactionStrategyInterface>
     */
    public function getStrategies(?string $profile = null): array
    {
        $config = RedactorConfig::fromConfig($profile);

        return $this->getStrategiesForProfile($config);
    }
}
