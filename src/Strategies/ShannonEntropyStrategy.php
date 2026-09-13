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
use Kirschbaum\Redactor\Support\Pcre;

/**
 * Finds tokens that look random enough to be a credential.
 *
 * Reports detections rather than rewriting, like every other detector, so an
 * entropy hit is scored, filtered by the confidence floor and handed to the
 * configured operator exactly as a pattern match is - and so a surrogate the
 * regex detector wrote a moment ago, which has the same entropy as the value
 * it replaced, is never mistaken for a fresh secret.
 */
class ShannonEntropyStrategy implements DetectingStrategy, Detector, RedactionStrategyInterface
{
    public const ENTITY = 'high_entropy';

    public const RULE = 'shannon_entropy';

    /**
     * How sure a bare entropy hit is on its own.
     *
     * Randomness is evidence of a secret, not proof: a base64 image chunk or
     * a git hash scores just as high. So an entropy detection starts at
     * medium, climbs with how far over the threshold it lands, and reaches
     * high only with a credential keyword beside it.
     */
    private const BASE_CONFIDENCE = 0.5;

    private const MARGIN_BOOST_CAP = 0.4;

    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        $shannonConfig = $context->config->shannonEntropy;

        if (! is_string($value) || ! ($shannonConfig['enabled'] ?? false)) {
            return false;
        }

        return ! $this->tooShort($value, $shannonConfig);
    }

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
     * Every whitespace-delimited token whose entropy clears its threshold.
     *
     * A value with no internal whitespace is a single token, so this
     * degenerates to reporting the whole value - the right answer for a bare
     * API key. A sentence with a secret embedded in it reports only the secret.
     *
     * @return array<int, Detection>
     */
    public function detect(string $subject, string $key, RedactionContext $context): array
    {
        if ($this->tooShort($subject, $context->config->shannonEntropy)) {
            return [];
        }

        // Spelled out rather than selected into a variable so the /u decision
        // is visible at the point it matters.
        $found = $this->isAscii($subject)
            ? @preg_match_all('/\S+/', $subject, $matches, PREG_OFFSET_CAPTURE)
            : @preg_match_all('/\S+/u', $subject, $matches, PREG_OFFSET_CAPTURE);

        if ($found === false || preg_last_error() !== PREG_NO_ERROR) {
            // The engine gave up. Fail closed rather than let a value the
            // tokeniser could not even split go out uninspected.
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
     * Whether a subject is pure ASCII, and so can use the cheaper patterns.
     *
     * The /u modifier makes PCRE validate the whole subject as UTF-8 on every
     * call, which for ASCII input buys nothing and costs a great deal: 40us
     * against 12us to split a 2.2KB string, on a path that runs over every
     * value scanned. Detecting ASCII costs about 1us, so the check pays for
     * itself many times over on exactly the long subjects where it matters.
     *
     * Dropping /u for non-ASCII input would be wrong rather than merely slower
     * - \s stops recognising Unicode whitespace, so tokens would join - which
     * is why the choice is made per subject rather than once for the profile.
     */
    protected function isAscii(string $value): bool
    {
        return preg_match('/[\x80-\xff]/', $value) !== 1;
    }

    /**
     * Whether a subject is too short to contain anything worth measuring.
     *
     * Checked twice over, cheapest first. A byte count is an upper bound on a
     * character count, so a subject under the minimum in bytes is certainly
     * under it in characters - which means the cheap test can only ever skip
     * work that was provably going to find nothing. Only what survives it pays
     * for the encoding check a character count requires.
     *
     * Applied at the value level as well as per token: a value shorter than
     * min_length cannot contain a token that long, so the whole tokenise pass
     * can be skipped. Most values in a log payload are well under it.
     *
     * @param  array<string, mixed>  $shannonConfig
     */
    protected function tooShort(string $subject, array $shannonConfig): bool
    {
        $minLength = $shannonConfig['min_length'] ?? 25;

        if (! is_numeric($minLength)) {
            return false;
        }

        $minLength = (int) $minLength;

        if (strlen($subject) < $minLength) {
            return true;
        }

        return $this->length($subject) < $minLength;
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
        $tokens = $this->isAscii($value)
            ? preg_split('/\s+/', $value, -1, PREG_SPLIT_NO_EMPTY)
            : preg_split('/\s+/u', $value, -1, PREG_SPLIT_NO_EMPTY);

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
        // mistaken for a long one - but the byte count settles most cases
        // first, without the encoding check that a character count needs.
        if ($this->tooShort($string, $shannonConfig)) {
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
