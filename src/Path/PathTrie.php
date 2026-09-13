<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Path;

use Kirschbaum\Redactor\Operators\OperatorSpec;

/**
 * Every configured path, compiled once into one structure.
 *
 * A naive implementation rebuilds the current path as a string at each node
 * and tests it against every pattern. A trie is walked in lockstep with the
 * payload instead, so the cost tracks the rules currently in play, which is
 * almost always zero or one. Deep wildcards make it an NFA rather than a
 * plain trie, since `**` can both absorb a segment and stand aside for the
 * next, so a cursor carries a set of states rather than a single one.
 */
class PathTrie
{
    private const int ROOT = 0;

    /** @var array<int, array<string, int>> literal segment => child node */
    private array $children = [self::ROOT => []];

    /** @var array<int, int|null> the `*` child of each node */
    private array $any = [self::ROOT => null];

    /** @var array<int, int|null> the `**` child of each node */
    private array $deep = [self::ROOT => null];

    /** @var array<int, bool> whether a node is itself a `**` node */
    private array $isDeep = [self::ROOT => false];

    /** @var array<int, array{spec: OperatorSpec, specificity: int, source: string}|null> */
    private array $terminal = [self::ROOT => null];

    private int $nextNode = 1;

    private bool $empty = true;

    /**
     * The compiled tries, keyed by the rule set that produced them.
     *
     * The profile config is resolved on every redaction, so without this the
     * trie would be rebuilt per call: measured at 0.23ms per call for 200
     * rules, several times the cost of the redaction itself.
     *
     * @var array<string, self>
     */
    private static array $memo = [];

    /**
     * Compile a set of path rules, reusing the trie for identical sets.
     *
     * @param  array<array-key, OperatorSpec>  $rules  path pattern => operator
     */
    public static function compile(array $rules): self
    {
        if ($rules === []) {
            return new self;
        }

        $cacheKey = self::cacheKey($rules);

        if (isset(self::$memo[$cacheKey])) {
            return self::$memo[$cacheKey];
        }

        $trie = new self;

        foreach ($rules as $pattern => $spec) {
            // PHP turns a purely numeric array key into an int, so a rule targeting a
            // list index arrives here as an integer and has to be put back...
            $trie->add(PathPattern::parse((string) $pattern), $spec);
        }

        return self::$memo[$cacheKey] = $trie;
    }

    /**
     * Identify a rule set by its patterns and what they do.
     *
     * Both halves matter: changing an operator without changing a pattern
     * must still produce a different trie, or a config change would silently
     * fail to take effect and turn a security setting into a no-op.
     *
     * @param  array<array-key, OperatorSpec>  $rules
     */
    private static function cacheKey(array $rules): string
    {
        $parts = [];

        foreach ($rules as $pattern => $spec) {
            $options = json_encode($spec->options);
            $parts[] = $pattern.'>'.$spec->name.'>'.($options === false ? '' : $options);
        }

        return implode("\0", $parts);
    }

    /**
     * Determine if the trie has no rules.
     */
    public function isEmpty(): bool
    {
        return $this->empty;
    }

    /**
     * Create a cursor positioned at the root.
     */
    public function cursor(): PathCursor
    {
        return new PathCursor($this, $this->empty ? [] : [self::ROOT]);
    }

    /**
     * Add a pattern to the trie.
     */
    private function add(PathPattern $pattern, OperatorSpec $spec): void
    {
        $this->empty = false;

        $node = self::ROOT;

        foreach ($pattern->segments as $segment) {
            $node = match ($segment) {
                PathPattern::DEEP => $this->deep[$node] ??= $this->createNode(isDeep: true),
                PathPattern::ANY => $this->any[$node] ??= $this->createNode(),
                default => $this->children[$node][$segment] ??= $this->createNode(),
            };
        }

        $existing = $this->terminal[$node];

        // Two patterns reaching the same node keep the more specific one, so the winner does not depend on declaration order...
        if ($existing === null || $pattern->specificity >= $existing['specificity']) {
            $this->terminal[$node] = [
                'spec' => $spec,
                'specificity' => $pattern->specificity,
                'source' => $pattern->source,
            ];
        }
    }

    /**
     * Create a new node and get its id.
     */
    private function createNode(bool $isDeep = false): int
    {
        $id = $this->nextNode++;

        $this->children[$id] = [];
        $this->any[$id] = null;
        $this->deep[$id] = null;
        $this->isDeep[$id] = $isDeep;
        $this->terminal[$id] = null;

        return $id;
    }

    /**
     * Advance a set of states by one path segment.
     *
     * @param  array<int, int>  $states
     * @return array<int, int>
     */
    public function advance(array $states, string $segment): array
    {
        if ($states === []) {
            return [];
        }

        $segment = strtolower($segment);
        $next = [];

        foreach ($states as $state) {
            // A `**` node absorbs this segment and stays in play for the next...
            if ($this->isDeep[$state]) {
                $next[$state] = $state;
            }

            $this->step($state, $segment, $next);

            // A `**` child can absorb this segment, or match zero segments and let what follows it match here instead...
            $deep = $this->deep[$state];

            if ($deep !== null) {
                $next[$deep] = $deep;
                $this->step($deep, $segment, $next);
            }
        }

        return $next;
    }

    /**
     * Follow the literal and `*` edges from a state.
     *
     * @param  array<int, int>  $next
     */
    private function step(int $state, string $segment, array &$next): void
    {
        $literal = $this->children[$state][$segment] ?? null;

        if ($literal !== null) {
            $next[$literal] = $literal;
        }

        $any = $this->any[$state];

        if ($any !== null) {
            $next[$any] = $any;
        }
    }

    /**
     * Get the winning operator among a set of states, if any of them is terminal.
     *
     * @param  array<int, int>  $states
     */
    public function match(array $states): ?PathMatch
    {
        $best = null;

        foreach ($states as $state) {
            $terminal = $this->terminal[$state] ?? null;

            if ($terminal === null) {
                continue;
            }

            if ($best === null || $terminal['specificity'] > $best['specificity']) {
                $best = $terminal;
            }
        }

        return $best === null
            ? null
            : new PathMatch($best['spec'], $best['source'], $best['specificity']);
    }
}
