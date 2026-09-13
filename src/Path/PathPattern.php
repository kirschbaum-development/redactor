<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Path;

use Kirschbaum\Redactor\Exceptions\ConfigurationException;

/**
 * A location in a payload, expressed as a dotted path.
 *
 *     request.headers.authorization    exactly there
 *     user.*.email                     any single level between
 *     **.password                      at any depth
 *     users[*].token                   through a list
 *
 * A key rule saying "anything called token" has to be applied to every key in
 * the payload and still cannot distinguish `auth.token` from
 * `pagination.token`. A path says exactly where, which is more precise and,
 * because it compiles into a trie the walk advances one step at a time,
 * considerably cheaper.
 */
final readonly class PathPattern
{
    /** Matches exactly one segment. */
    public const ANY = '*';

    /** Matches zero or more segments. */
    public const DEEP = '**';

    /**
     * Create a new path pattern instance.
     *
     * @param  array<int, string>  $segments
     */
    private function __construct(
        public string $source,
        public array $segments,
        public int $specificity,
    ) {}

    /**
     * Parse a dotted path pattern.
     *
     * @throws ConfigurationException
     */
    public static function parse(string $pattern): self
    {
        $normalised = self::normalise($pattern);

        if ($normalised === []) {
            throw new ConfigurationException(sprintf(
                'Redactor path pattern [%s] is empty.',
                $pattern
            ));
        }

        return new self($pattern, $normalised, self::score($normalised));
    }

    /**
     * Split a pattern into segments, turning list syntax into ordinary ones.
     *
     * `users[*].email` and `users.*.email` describe the same place; accepting
     * both means nobody has to remember which spelling this library chose.
     *
     * @return array<int, string>
     */
    private static function normalise(string $pattern): array
    {
        // users[*] becomes users.* and items[0] becomes items.0...
        $expanded = preg_replace('/\[([^\]]*)\]/', '.$1', $pattern) ?? $pattern;
        $expanded = str_replace('..', '.', $expanded);

        $segments = [];

        foreach (explode('.', $expanded) as $segment) {
            $segment = trim($segment);

            if ($segment === '') {
                // An empty `[]` means "any index", and a stray dot is noise...
                continue;
            }

            $segments[] = strtolower($segment);
        }

        return $segments;
    }

    /**
     * Score how specific a pattern is, for resolving overlaps.
     *
     * A literal segment says the most, a single-level wildcard less, and a
     * deep wildcard least, so `request.headers.authorization` beats
     * `request.headers.*`, which beats `**.authorization`. Without an ordering
     * the winner would depend on config order.
     *
     * @param  array<int, string>  $segments
     */
    private static function score(array $segments): int
    {
        $score = 0;

        foreach ($segments as $segment) {
            $score += match ($segment) {
                self::DEEP => 1,
                self::ANY => 2,
                default => 3,
            };
        }

        return $score;
    }
}
