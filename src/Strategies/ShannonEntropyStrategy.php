<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\Detection\Confidence;
use Kirschbaum\Redactor\Detection\Detection;
use Kirschbaum\Redactor\Detection\Detector;
use Kirschbaum\Redactor\Detection\KeywordContext;
use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Strategies\Contracts\DetectingStrategy;
use Kirschbaum\Redactor\Strategies\Contracts\Strategy;
use Kirschbaum\Redactor\Support\Pcre;

/**
 * Finds tokens that look random enough to be a credential.
 *
 * Reports detections rather than rewriting, like every other detector, so an
 * entropy hit is scored, filtered by the confidence floor and handed to the
 * configured operator exactly as a pattern match is, and a surrogate the regex
 * detector just wrote, which has the same entropy as the value it replaced, is
 * never mistaken for a fresh secret.
 */
class ShannonEntropyStrategy implements DetectingStrategy, Detector, Strategy
{
    public const ENTITY = 'high_entropy';

    public const RULE = 'shannon_entropy';

    /**
     * The confidence of a bare entropy hit on its own.
     *
     * Randomness is evidence of a secret, not proof: a base64 image chunk or a
     * git hash scores just as high. A detection starts at medium, climbs with
     * its margin over the threshold, and reaches high only with a keyword.
     */
    private const BASE_CONFIDENCE = 0.5;

    private const MARGIN_BOOST_CAP = 0.4;

    /**
     * Determine if the value is a string long enough to measure.
     */
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        $shannonConfig = $context->config->shannonEntropy;

        if (! is_string($value) || ! ($shannonConfig['enabled'] ?? false)) {
            return false;
        }

        return ! $this->tooShort($value, $shannonConfig);
    }

    /**
     * Collect every high-entropy token in the value.
     */
    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        if (! is_string($value)) {
            return $value;
        }

        foreach ($this->detect($value, $key, $context) as $detection) {
            $context->collect($detection);
        }

        return $value;
    }

    /**
     * Get every whitespace-delimited token whose entropy clears its threshold.
     *
     * A value with no internal whitespace is a single token, so a bare API key
     * is reported whole; a sentence with a secret in it reports only the secret.
     *
     * @return array<int, Detection>
     */
    public function detect(string $subject, string $key, RedactionContext $context): array
    {
        if ($this->tooShort($subject, $context->config->shannonEntropy)) {
            return [];
        }

        // Only tokens at least min_length long can qualify and a byte count bounds a
        // character count, so asking PCRE for `\S{n,}` is exact and turns a million-byte
        // subject into a few hundred candidates instead of hundreds of thousands...
        $minimum = max(1, $this->minimumLength($context->config->shannonEntropy));

        // Spelled out rather than selected into a variable so the /u decision is visible where it matters...
        $found = $this->isAscii($subject)
            ? @preg_match_all('/\S{'.$minimum.',}/', $subject, $matches, PREG_OFFSET_CAPTURE)
            : @preg_match_all('/\S{'.$minimum.',}/u', $subject, $matches, PREG_OFFSET_CAPTURE);

        if ($found === false || preg_last_error() !== PREG_NO_ERROR) {
            // The engine gave up, so fail closed rather than let a value the tokeniser could not split go out uninspected...
            Pcre::matches('/\S+/u', $subject, onError: true, rule: self::RULE);

            return [Detection::failClosed(
                self::ENTITY,
                self::RULE,
                $subject,
                $key,
                'the value could not be tokenised; failing closed'
            )];
        }

        $detections = [];

        foreach ($matches[0] as [$token, $offset]) {
            $token = (string) $token;
            $offset = (int) $offset;

            if ($token === '' || ! $this->shouldRedactByEntropy($token, $context)) {
                continue;
            }

            $detections[] = new Detection(
                entity: self::ENTITY,
                rule: self::RULE,
                offset: $offset,
                value: $token,
                confidence: $this->score($token, $subject, $offset, $key, $context),
                key: $key,
            );
        }

        return $detections;
    }

    /**
     * Score a token by how far its entropy clears the threshold, plus context.
     */
    protected function score(string $token, string $subject, int $offset, string $key, RedactionContext $context): Confidence
    {
        $entropy = $this->calculateShannonEntropy($token, $context);
        $threshold = $this->thresholdFor($token, $context);

        $confidence = Confidence::of(
            self::BASE_CONFIDENCE,
            sprintf('entropy %.2f bits/char over the %.2f threshold', $entropy, $threshold)
        );

        $margin = min(self::MARGIN_BOOST_CAP, max(0.0, ($entropy - $threshold) / 2));

        if ($margin > 0.0) {
            $confidence = $confidence->with('margin', $margin, 'well clear of the threshold');
        }

        return KeywordContext::boost($confidence, $subject, $offset, $key);
    }

    /**
     * Determine if a subject is pure ASCII and can use the cheaper patterns.
     *
     * The /u modifier makes PCRE validate the whole subject as UTF-8 on every
     * call, 40us against 12us to split a 2.2KB string, on a path that runs
     * over every value. Dropping /u for non-ASCII input would be wrong rather
     * than slower, since \s would stop recognising Unicode whitespace.
     */
    protected function isAscii(string $value): bool
    {
        return preg_match('/[\x80-\xff]/', $value) !== 1;
    }

    /**
     * Determine if a subject is too short to contain anything worth measuring.
     *
     * A byte count is an upper bound on a character count, so a subject under
     * the minimum in bytes is certainly under it in characters, and only what
     * survives that test pays for the encoding check. Applied per value as
     * well as per token, since most values in a log payload are well under it.
     *
     * @param  array<string, mixed>  $shannonConfig
     */
    protected function tooShort(string $subject, array $shannonConfig): bool
    {
        $minLength = $this->minimumLength($shannonConfig);

        if (strlen($subject) < $minLength) {
            return true;
        }

        return $this->length($subject) < $minLength;
    }

    /**
     * Get the configured minimum token length, or zero when there is none.
     *
     * @param  array<string, mixed>  $shannonConfig
     */
    protected function minimumLength(array $shannonConfig): int
    {
        $minLength = $shannonConfig['min_length'] ?? 25;

        return is_numeric($minLength) ? max(0, (int) $minLength) : 0;
    }

    /**
     * Split a string into characters, falling back to bytes for input that is not valid UTF-8.
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
     * Get the character count, or the byte count for non-UTF-8 input.
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
        $tokens = $this->isAscii($value)
            ? preg_split('/\s+/', $value, -1, PREG_SPLIT_NO_EMPTY)
            : preg_split('/\s+/u', $value, -1, PREG_SPLIT_NO_EMPTY);

        return $tokens === false ? [$value] : $tokens;
    }

    /**
     * The charsets a token can be drawn from, most restrictive first.
     *
     * A 40-character hex digest tops out at 4 bits per character because it
     * has only 16 symbols, so judging it against a base64 threshold guarantees
     * a miss and the reverse guarantees false positives. detect-secrets solves
     * this the same way: pick the threshold from the alphabet.
     *
     * @var array<string, string>
     */
    protected const CHARSET_PATTERNS = [
        'hex' => '/^[0-9a-f]+$/i',
        'base64' => '/^[A-Za-z0-9+\/]+={0,2}$/',
        'base64url' => '/^[A-Za-z0-9_-]+$/',
    ];

    /**
     * Determine if a token's entropy clears its threshold.
     */
    protected function shouldRedactByEntropy(string $string, RedactionContext $context): bool
    {
        $shannonConfig = $context->config->shannonEntropy;

        // Counted in characters, not bytes, so a short multibyte token is not mistaken for a long one...
        if ($this->tooShort($string, $shannonConfig)) {
            return false;
        }

        // Skip configured exclusions that score high without being sensitive...
        if ($this->isCommonPattern($string, $context->config)) {
            return false;
        }

        $entropy = $this->calculateShannonEntropy($string, $context);

        return $entropy >= $this->thresholdFor($string, $context);
    }

    /**
     * Get the entropy threshold to judge this particular token against.
     *
     * charset_thresholds is an opt-in refinement: when a profile configures
     * one for the token's alphabet it wins, otherwise the profile's single
     * `threshold` applies. An explicit threshold is never silently overridden.
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
     * Pass a context to reuse and populate its per-redaction entropy cache.
     */
    public function calculateShannonEntropy(string $string, ?RedactionContext $context = null): float
    {
        $cachedEntropy = $context?->getCachedEntropy($string);
        if ($cachedEntropy !== null) {
            return $cachedEntropy;
        }

        // Measured in characters, since counting UTF-8 continuation bytes as symbols inflates entropy for non-ASCII text...
        $characters = $this->characters($string);
        $length = count($characters);

        if ($length <= 1) {
            $entropy = 0.0;
            $context?->cacheEntropy($string, $entropy);

            return $entropy;
        }

        $frequencies = [];
        foreach ($characters as $char) {
            $frequencies[$char] = ($frequencies[$char] ?? 0) + 1;
        }

        $entropy = 0.0;
        foreach ($frequencies as $frequency) {
            $probability = $frequency / $length;
            if ($probability > 0) {
                $entropy -= $probability * log($probability, 2);
            }
        }

        $context?->cacheEntropy($string, $entropy);

        return $entropy;
    }

    /**
     * Determine if a string matches a configured exclusion pattern and should be left alone.
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

            // onError: false, since an exclusion pattern that cannot be evaluated must not excuse the value...
            if (Pcre::matches($pattern, $string, onError: false, rule: 'exclusion_pattern')) {
                // A long hex string may be a digest such as SHA-256, so the hex exclusion does not excuse it...
                if ($pattern === '/^[0-9a-f]+$/i' && strlen($string) >= 32) {
                    continue;
                }

                return true;
            }
        }

        return false;
    }
}
