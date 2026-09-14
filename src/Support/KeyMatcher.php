<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Support;

/**
 * A key-pattern list compiled once into the cheapest test for each shape.
 *
 * Rebuilding a regex for every wildcard pattern, for every key, on every call
 * was the hottest operation in a redaction at ~1.2us per key against ~0.1us
 * for an exact match. Almost every real pattern is an exact name or a plain
 * contains, so those become a hash lookup and a str_contains(); only a
 * genuinely complex pattern like "user_*_token" reaches PCRE, compiled once.
 * Keys and patterns are compared lowercased.
 */
class KeyMatcher
{
    /** @var array<string, self> */
    private static array $memo = [];

    /** @var array<string, true> */
    private array $exact = [];

    /** @var array<int, string> */
    private array $contains = [];

    /** @var array<int, string> */
    private array $prefix = [];

    /** @var array<int, string> */
    private array $suffix = [];

    /** @var array<int, array{pattern: string, source: string}> */
    private array $regex = [];

    private bool $matchesEverything = false;

    private bool $empty = true;

    /**
     * Create a new key matcher instance.
     *
     * @param  array<int, string>  $patterns
     */
    private function __construct(array $patterns)
    {
        foreach ($patterns as $pattern) {
            $this->compile(strtolower($pattern));
        }
    }

    /**
     * Compile a pattern list, reusing the result for identical lists.
     *
     * @param  array<int, string>  $patterns
     */
    public static function for(array $patterns): self
    {
        $cacheKey = implode("\0", $patterns);

        return self::$memo[$cacheKey] ??= new self($patterns);
    }

    /**
     * Flush the compiled matcher cache.
     */
    public static function flush(): void
    {
        self::$memo = [];
    }

    /**
     * Determine if the matcher has no patterns.
     */
    public function isEmpty(): bool
    {
        return $this->empty;
    }

    /**
     * Determine if the key matches any compiled pattern.
     *
     * @param  bool  $onError  what a PCRE failure should be reported as
     */
    public function matches(string $key, bool $onError = true): bool
    {
        if ($this->empty || $key === '') {
            return false;
        }

        if ($this->matchesEverything) {
            return true;
        }

        $key = strtolower($key);

        if (isset($this->exact[$key])) {
            return true;
        }

        foreach ($this->contains as $needle) {
            if (str_contains($key, $needle)) {
                return true;
            }
        }

        foreach ($this->prefix as $needle) {
            if (str_starts_with($key, $needle)) {
                return true;
            }
        }

        foreach ($this->suffix as $needle) {
            if (str_ends_with($key, $needle)) {
                return true;
            }
        }

        foreach ($this->regex as $compiled) {
            if (Pcre::matches($compiled['pattern'], $key, $onError, 'key_pattern:'.$compiled['source'])) {
                return true;
            }
        }

        return false;
    }

    /**
     * Compile one pattern into the cheapest test for its shape.
     */
    private function compile(string $pattern): void
    {
        if ($pattern === '') {
            return;
        }

        $this->empty = false;

        if (! str_contains($pattern, '*')) {
            $this->exact[$pattern] = true;

            return;
        }

        if (trim($pattern, '*') === '') {
            // '*', '**' and so on match everything...
            $this->matchesEverything = true;

            return;
        }

        $core = trim($pattern, '*');

        // Only the outer wildcards are special-cased, since an interior '*' needs real backtracking and goes to PCRE...
        if (! str_contains($core, '*')) {
            $leading = str_starts_with($pattern, '*');
            $trailing = str_ends_with($pattern, '*');

            if ($leading && $trailing) {
                $this->contains[] = $core;

                return;
            }

            if ($trailing) {
                $this->prefix[] = $core;

                return;
            }

            $this->suffix[] = $core;

            return;
        }

        $this->regex[] = [
            'pattern' => '/^'.str_replace('\*', '.*', preg_quote($pattern, '/')).'$/i',
            'source' => $pattern,
        ];
    }
}
