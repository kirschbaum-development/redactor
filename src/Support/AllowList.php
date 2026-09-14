<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Support;

/**
 * Values that are never sensitive, however much they look it.
 *
 * Every detector is a guess about content, and some content is known: the
 * support address on every page, the sandbox card number in every fixture.
 * Listing them here beats weakening a pattern to avoid them. An entry is a
 * literal, compared case-insensitively after trimming, or a regex when it is
 * delimited like one. A regex that cannot be evaluated allows nothing: the
 * failure mode of an allow-list is a leak, not noise.
 */
class AllowList
{
    /** @var array<string, self> */
    private static array $memo = [];

    /** @var array<string, true> */
    private array $exact = [];

    /** @var array<int, string> */
    private array $patterns = [];

    /**
     * Create a new allow list instance.
     *
     * @param  array<int, string>  $entries
     */
    private function __construct(array $entries)
    {
        foreach ($entries as $entry) {
            $entry = trim($entry);

            if ($entry === '') {
                continue;
            }

            if ($this->looksLikeRegex($entry) && Pcre::isValidPattern($entry)) {
                $this->patterns[] = $entry;

                continue;
            }

            $this->exact[mb_strtolower($entry)] = true;
        }
    }

    /**
     * Compile an entry list, reusing the result for identical lists.
     *
     * @param  array<int, string>  $entries
     */
    public static function for(array $entries): self
    {
        $cacheKey = implode("\0", $entries);

        return self::$memo[$cacheKey] ??= new self($entries);
    }

    /**
     * Get an empty allow list.
     */
    public static function none(): self
    {
        return self::for([]);
    }

    /**
     * Determine if the list has no entries.
     */
    public function isEmpty(): bool
    {
        return $this->exact === [] && $this->patterns === [];
    }

    /**
     * Determine if the value is allowed.
     */
    public function allows(string $value): bool
    {
        if ($this->isEmpty()) {
            return false;
        }

        if (isset($this->exact[mb_strtolower(trim($value))])) {
            return true;
        }

        foreach ($this->patterns as $pattern) {
            // onError: false, since an entry that cannot be evaluated excuses nothing...
            if (Pcre::matches($pattern, $value, onError: false, rule: 'allowlist')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine if an entry has a leading delimiter that closes before an optional modifier suffix.
     */
    private function looksLikeRegex(string $entry): bool
    {
        if (strlen($entry) < 3) {
            return false;
        }

        $delimiter = $entry[0];

        if (ctype_alnum($delimiter) || $delimiter === '\\' || ctype_space($delimiter)) {
            return false;
        }

        $close = match ($delimiter) {
            '(' => ')',
            '[' => ']',
            '{' => '}',
            '<' => '>',
            default => $delimiter,
        };

        return preg_match('/'.preg_quote($close, '/').'[imsxuADSUXJn]*$/', substr($entry, 1)) === 1;
    }
}
