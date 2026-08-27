<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Strategies\Contracts\ChainableStrategy;
use Kirschbaum\Redactor\Support\Pcre;

class ShannonEntropyStrategy implements ChainableStrategy, RedactionStrategyInterface
{
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        $shannonConfig = $context->config->shannonEntropy;

        if (! is_string($value) || ! ($shannonConfig['enabled'] ?? false)) {
            return false;
        }

        foreach ($this->tokenize($value) as $token) {
            if ($this->shouldRedactByEntropy($token, $context)) {
                return true;
            }
        }

        return false;
    }

    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        if (! is_string($value)) {
            return $value;
        }

        $replacement = $context->config->replacement;

        // A value with no internal whitespace is a single token, so this
        // degenerates to replacing the whole value - the pre-existing
        // behaviour for API keys and the like. A sentence with a secret
        // embedded in it loses only the secret.
        $result = preg_replace_callback(
            '/\S+/u',
            function (array $matches) use ($context, $replacement): string {
                $token = (string) $matches[0];

                return $this->shouldRedactByEntropy($token, $context) ? $replacement : $token;
            },
            $value
        );

        if ($result === null || $result === $value) {
            // preg failed, or nothing matched (a whitespace-only string that
            // somehow reached here). Fail closed on the former.
            if ($result === null) {
                $context->recordRedaction($key, 'shannon_entropy');

                return $replacement;
            }

            return $value;
        }

        $context->recordRedaction($key, 'shannon_entropy');

        return $result;
    }

    /**
     * Split a value into the tokens entropy is measured over.
     *
     * @return array<int, string>
     */
    protected function tokenize(string $value): array
    {
        $tokens = preg_split('/\s+/u', $value, -1, PREG_SPLIT_NO_EMPTY);

        return $tokens === false ? [$value] : $tokens;
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
