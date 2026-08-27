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

        /** @var array<int, array{offset: int, length: int, matched: string}> $hits */
        $hits = [];

        // A value with no internal whitespace is a single token, so this
        // degenerates to replacing the whole value - the pre-existing
        // behaviour for API keys and the like. A sentence with a secret
        // embedded in it loses only the secret.
        $result = preg_replace_callback(
            '/\S+/u',
            function (array $matches) use ($context, $replacement, &$hits): string {
                [$token, $offset] = $matches[0];

                if (! $this->shouldRedactByEntropy((string) $token, $context)) {
                    return (string) $token;
                }

                $hits[] = [
                    'offset' => (int) $offset,
                    'length' => strlen((string) $token),
                    'matched' => (string) $token,
                ];

                return $replacement;
            },
            $value,
            -1,
            $count,
            PREG_OFFSET_CAPTURE
        );

        if ($result === null) {
            // The engine gave up. Fail closed rather than emit a partially
            // substituted string.
            $context->recordRedaction($key, 'shannon_entropy', 0, strlen($value));

            return $replacement;
        }

        if ($hits === []) {
            return $value;
        }

        foreach ($hits as $hit) {
            $context->recordRedaction($key, 'shannon_entropy', $hit['offset'], $hit['length'], $hit['matched']);
        }

        return $result;
    }

    /**
     * Split a string into characters, falling back to bytes for input that is
     * not valid UTF-8 (binary blobs reach this during file scanning).
     *
     * @return array<int, string>
     */
    protected function characters(string $string): array
    {
        if (! mb_check_encoding($string, 'UTF-8')) {
            return str_split($string);
        }

        $characters = mb_str_split($string, 1, 'UTF-8');

        return $characters === [] ? str_split($string) : $characters;
    }

    /**
     * Character count, byte count for non-UTF-8 input.
     */
    protected function length(string $string): int
    {
        return mb_check_encoding($string, 'UTF-8')
            ? mb_strlen($string, 'UTF-8')
            : strlen($string);
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
     * Charsets a token can be drawn from, most restrictive first.
     *
     * A 40-character hex digest tops out at 4 bits of entropy per character
     * because it only has 16 symbols to draw on, so judging it against a
     * base64 threshold guarantees a miss. Judging base64 against a hex
     * threshold guarantees false positives. detect-secrets solves this the
     * same way: pick the threshold from the alphabet.
     *
     * @var array<string, string>
     */
    protected const CHARSET_PATTERNS = [
        'hex' => '/^[0-9a-f]+$/i',
        'base64' => '/^[A-Za-z0-9+\/]+={0,2}$/',
        'base64url' => '/^[A-Za-z0-9_-]+$/',
    ];

    /**
     * Determine if a string should be redacted based on Shannon entropy.
     */
    protected function shouldRedactByEntropy(string $string, RedactionContext $context): bool
    {
        $shannonConfig = $context->config->shannonEntropy;

        // Only analyze strings that meet minimum length requirement.
        // Counted in characters, not bytes, so a short multibyte token is not
        // mistaken for a long one.
        $minLength = $shannonConfig['min_length'] ?? 25;
        if ($this->length($string) < $minLength) {
            return false;
        }

        // Skip common words and patterns that might have high entropy but are not sensitive
        if ($this->isCommonPattern($string, $context->config)) {
            return false;
        }

        $entropy = $this->calculateShannonEntropy($string, $context);

        return $entropy >= $this->thresholdFor($string, $context);
    }

    /**
     * The entropy threshold to judge this particular token against.
     *
     * charset_thresholds is an opt-in refinement: when a profile configures
     * one for the token's alphabet it wins, otherwise the profile's single
     * `threshold` applies. An explicitly configured threshold is never
     * overridden by a value the operator cannot see.
     */
    protected function thresholdFor(string $string, RedactionContext $context): float
    {
        $shannonConfig = $context->config->shannonEntropy;

        $configured = $shannonConfig['charset_thresholds'] ?? [];

        if (is_array($configured) && $configured !== []) {
            $charset = $this->detectCharset($string);

            if ($charset !== null && is_numeric($configured[$charset] ?? null)) {
                /** @var numeric $value */
                $value = $configured[$charset];

                return (float) $value;
            }
        }

        $fallback = $shannonConfig['threshold'] ?? 4.8;

        return is_numeric($fallback) ? (float) $fallback : 4.8;
    }

    /**
     * Identify the alphabet a token is drawn from, if it is a recognised one.
     */
    protected function detectCharset(string $string): ?string
    {
        foreach (self::CHARSET_PATTERNS as $name => $pattern) {
            if (Pcre::matches($pattern, $string, onError: false, rule: 'charset:'.$name)) {
                return $name;
            }
        }

        return null;
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

        // Split into characters, not bytes: measuring UTF-8 by byte counts
        // the same character's continuation bytes as separate symbols, which
        // inflates entropy for any non-ASCII text.
        $characters = $this->characters($string);
        $length = count($characters);

        if ($length <= 1) {
            $entropy = 0.0;
            $context?->cacheEntropy($string, $entropy);

            return $entropy;
        }

        // Count character frequencies and calculate entropy in a single loop
        $frequencies = [];
        foreach ($characters as $char) {
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
