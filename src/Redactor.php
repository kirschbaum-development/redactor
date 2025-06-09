<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Kirschbaum\Redactor\Strategies\LargeObjectStrategy;
use Kirschbaum\Redactor\Strategies\RedactionStrategyInterface;
use Kirschbaum\Redactor\Strategies\ShannonEntropyStrategy;

class Redactor
{
    /** @var array<string, array<RedactionStrategyInterface>> */
    private array $profileStrategies = [];

    /** @var array<string, RedactionStrategyInterface> */
    private array $customStrategies = [];

    public function __construct()
    {
        $this->loadCustomStrategies();
    }

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

        return $redactedContent ?? $content;
    }

    /**
     * Get strategies for a specific profile.
     *
     * @return array<RedactionStrategyInterface>
     */
    private function getStrategiesForProfile(RedactorConfig $config): array
    {
        $profileName = $config->profile;

        if (! isset($this->profileStrategies[$profileName])) {
            $this->profileStrategies[$profileName] = $this->buildStrategiesForProfile($config);
        }

        return $this->profileStrategies[$profileName];
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
        if (is_array($data)) {
            /** @var array<string, mixed> $arrayData */
            $arrayData = $data;

            return $this->redactArray($arrayData, $context, $strategies);
        }

        if (is_object($data)) {
            return $this->redactObject($data, $key, $context, $strategies);
        }

        // Apply strategies to scalar values
        return $this->applyStrategies($data, $key, $context, $strategies);
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
        $arrayAsValue = $this->applyStrategies($array, '', $context, $strategies);
        if ($arrayAsValue !== $array) {
            // Array was redacted by a strategy (e.g., LargeObjectStrategy)
            if (is_array($arrayAsValue)) {
                /** @var array<string, mixed> $typedArray */
                $typedArray = $arrayAsValue;

                return $typedArray;
            }

            return ['_redacted_array' => $arrayAsValue];
        }

        /** @var array<string, mixed> $result */
        $result = [];

        foreach ($array as $key => $value) {
            $keyString = (string) $key;

            // Apply strategies to the key-value pair
            $processedValue = $this->applyStrategies($value, $keyString, $context, $strategies);

            // Handle object removal case
            if ($processedValue === '__REDACTOR_REMOVE_OBJECT__') {
                continue; // Skip adding this key to the result
            }

            // If the value wasn't handled by key-based strategies, process recursively
            if ($processedValue === $value && (is_array($value) || is_object($value))) {
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
        $objectAsValue = $this->applyStrategies($object, $key, $context, $strategies);
        if ($objectAsValue !== $object) {
            return $objectAsValue;
        }

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
                Log::warning('Unable to redact object - JSON decode did not return array', [
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
            Log::warning('Exception while trying to redact object', [
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
    protected function applyStrategies(mixed $value, string $key, RedactionContext $context, array $strategies): mixed
    {
        foreach ($strategies as $strategy) {
            if ($strategy->shouldHandle($value, $key, $context)) {
                return $strategy->handle($value, $key, $context);
            }
        }

        return $value; // No strategy handled this value
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

    // Legacy methods for backward compatibility

    /**
     * Add a custom strategy to the redactor.
     *
     * @deprecated Use registerCustomStrategy instead
     */
    public function addStrategy(RedactionStrategyInterface $strategy): void
    {
        // For backward compatibility, add to default profile
        $defaultProfile = Config::get('redactor.default_profile', 'default');
        $this->registerCustomStrategy('custom_'.uniqid(), $strategy);
    }

    /**
     * Remove a strategy from the redactor.
     *
     * @deprecated Strategy removal should be handled via profile configuration
     */
    public function removeStrategy(string $strategyClass): void
    {
        // Clear cached strategies to force rebuild
        $this->profileStrategies = [];
    }

    /**
     * Calculate Shannon entropy of a string (for testing purposes).
     * Delegates to the ShannonEntropyStrategy.
     */
    public function calculateShannonEntropy(string $string): float
    {
        $config = RedactorConfig::fromConfig();
        $context = new RedactionContext($config);
        $strategies = $this->getStrategiesForProfile($config);

        foreach ($strategies as $strategy) {
            if ($strategy instanceof ShannonEntropyStrategy) {
                $reflection = new \ReflectionClass($strategy);
                $method = $reflection->getMethod('calculateShannonEntropy');
                $method->setAccessible(true);

                $result = $method->invoke($strategy, $string, $context);

                return is_float($result) ? $result : 0.0;
            }
        }

        return 0.0;
    }

    /**
     * Check if a string matches common patterns (for testing purposes).
     * Delegates to the ShannonEntropyStrategy.
     */
    public function isCommonPattern(string $string, RedactorConfig $config): bool
    {
        $context = new RedactionContext($config);
        $strategies = $this->getStrategiesForProfile($config);

        foreach ($strategies as $strategy) {
            if ($strategy instanceof ShannonEntropyStrategy) {
                $reflection = new \ReflectionClass($strategy);
                $method = $reflection->getMethod('isCommonPattern');
                $method->setAccessible(true);

                $result = $method->invoke($strategy, $string, $context);

                return is_bool($result) ? $result : false;
            }
        }

        return false;
    }
}
