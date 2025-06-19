<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\RedactionContext;

class ShannonEntropyStrategy implements RedactionStrategyInterface
{
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        $shannonConfig = $context->config->shannonEntropy;

        if (! is_string($value) || ! ($shannonConfig['enabled'] ?? false)) {
            return false;
        }

        return $this->shouldRedactByEntropy($value, $context);
    }

    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        $context->markRedacted();

        return $context->config->replacement;
    }

    /**
     * Determine if a string should be redacted based on Shannon entropy.
     */
    protected function shouldRedactByEntropy(string $string, RedactionContext $context): bool
    {
        $shannonConfig = $context->config->shannonEntropy;

        // Only analyze strings that meet minimum length requirement
        $minLength = $shannonConfig['min_length'] ?? 25;
        if (strlen($string) < $minLength) {
            return false;
        }

        // Skip common words and patterns that might have high entropy but are not sensitive
        if ($this->isCommonPattern($string, $context)) {
            return false;
        }

        $entropy = $this->calculateShannonEntropy($string, $context);
        $threshold = $shannonConfig['threshold'] ?? 4.8;

        return $entropy >= $threshold;
    }

    /**
     * Calculate Shannon entropy of a string with caching.
     */
    protected function calculateShannonEntropy(string $string, RedactionContext $context): float
    {
        // Check cache first
        $cachedEntropy = $context->getCachedEntropy($string);
        if ($cachedEntropy !== null) {
            return $cachedEntropy;
        }

        $length = strlen($string);
        if ($length <= 1) {
            $entropy = 0.0;
            $context->cacheEntropy($string, $entropy);

            return $entropy;
        }

        // Count character frequencies and calculate entropy in a single loop
        $frequencies = [];
        for ($i = 0; $i < $length; $i++) {
            $char = $string[$i];
            $frequencies[$char] = ($frequencies[$char] ?? 0) + 1;
        }

        // Calculate entropy
        $entropy = 0.0;
        foreach ($frequencies as $frequency) {
            $probability = $frequency / $length;
            if ($probability > 0) {
                $entropy -= $probability * log($probability, 2);
            }
        }

        // Cache the result
        $context->cacheEntropy($string, $entropy);

        return $entropy;
    }

    /**
     * Check if a string matches common patterns that shouldn't be redacted despite high entropy.
     */
    protected function isCommonPattern(string $string, RedactionContext $context): bool
    {
        $shannonConfig = $context->config->shannonEntropy;
        $exclusionPatterns = $shannonConfig['exclusion_patterns'] ?? [];

        if (! is_array($exclusionPatterns)) {
            return false;
        }

        foreach ($exclusionPatterns as $pattern) {
            if (! is_string($pattern)) {
                continue;
            }

            if (preg_match($pattern, $string)) {
                // Special case: hex strings need additional length check
                if ($pattern === '/^[0-9a-f]+$/i' && strlen($string) >= 32) {
                    continue; // Long hex strings might be sensitive (like SHA256)
                }

                return true;
            }
        }

        return false;
    }
}
