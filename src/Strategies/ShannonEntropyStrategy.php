<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Support\Pcre;

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
        if ($this->isCommonPattern($string, $context->config)) {
            return false;
        }

        $entropy = $this->calculateShannonEntropy($string, $context);
        $threshold = $shannonConfig['threshold'] ?? 4.8;

        return $entropy >= $threshold;
    }

    /**
     * Calculate the Shannon entropy of a string, in bits per character.
     *
     * Pass a context to reuse (and populate) its per-redaction entropy cache.
     */
    public function calculateShannonEntropy(string $string, ?RedactionContext $context = null): float
    {
        // Check cache first
        $cachedEntropy = $context?->getCachedEntropy($string);
        if ($cachedEntropy !== null) {
            return $cachedEntropy;
        }

        $length = strlen($string);
        if ($length <= 1) {
            $entropy = 0.0;
            $context?->cacheEntropy($string, $entropy);

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
        $context?->cacheEntropy($string, $entropy);

        return $entropy;
    }

    /**
     * Check if a string matches a configured exclusion pattern, meaning it should
     * not be redacted despite scoring above the entropy threshold.
     */
    public function isCommonPattern(string $string, RedactorConfig $config): bool
    {
        $shannonConfig = $config->shannonEntropy;
        $exclusionPatterns = $shannonConfig['exclusion_patterns'] ?? [];

        if (! is_array($exclusionPatterns)) {
            return false;
        }

        foreach ($exclusionPatterns as $pattern) {
            if (! is_string($pattern)) {
                continue;
            }

            // onError: false. An exclusion pattern that cannot be evaluated
            // must not excuse the value from the entropy check.
            if (Pcre::matches($pattern, $string, onError: false, rule: 'exclusion_pattern')) {
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
