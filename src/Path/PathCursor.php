<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Path;

/**
 * Where the walk currently is, in terms of the compiled path rules.
 *
 * Immutable and cheap: descending returns a new cursor holding the states now
 * in play, so the walk can hand a child its own cursor without any of the
 * unwinding that mutable position-tracking needs.
 *
 * An exhausted cursor - no active states - can never match again, so the walk
 * can stop consulting paths entirely for that subtree.
 */
final readonly class PathCursor
{
    /**
     * @param  array<int, int>  $states
     */
    public function __construct(
        private PathTrie $trie,
        private array $states = [],
    ) {}

    public function descend(string $segment): self
    {
        return $this->states === []
            ? $this
            : new self($this->trie, $this->trie->advance($this->states, $segment));
    }

    public function match(): ?PathMatch
    {
        return $this->states === [] ? null : $this->trie->match($this->states);
    }

    /**
     * Whether this cursor can still lead anywhere.
     */
    public function isExhausted(): bool
    {
        return $this->states === [];
    }
}
