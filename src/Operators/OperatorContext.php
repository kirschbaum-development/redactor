<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators;

use Closure;
use Kirschbaum\Redactor\Support\Pseudonymizer;

/**
 * Everything an operator is allowed to know.
 *
 * Deliberately narrow: operators receive the replacement string, their own
 * options and the pseudonymizer, and nothing else. They cannot reach the
 * payload, the profile or the container, which keeps them pure enough to test
 * in isolation and impossible to turn into a second detection layer.
 */
class OperatorContext
{
    private ?Pseudonymizer $resolved = null;

    private bool $isResolved = false;

    /**
     * Create a new operator context instance.
     *
     * @param  array<string, mixed>  $options
     * @param  Pseudonymizer|Closure(): ?Pseudonymizer|null  $pseudonymizer  the pseudonymizer, or a resolver for one
     */
    public function __construct(
        public readonly string $replacement,
        public readonly array $options = [],
        private readonly Pseudonymizer|Closure|null $pseudonymizer = null,
    ) {}

    /**
     * Get the pseudonymizer, resolving it on first use.
     *
     * Only operators that pseudonymise pay for the key derivation.
     */
    public function pseudonymizer(): ?Pseudonymizer
    {
        if ($this->isResolved) {
            return $this->resolved;
        }

        $this->isResolved = true;
        $this->resolved = $this->pseudonymizer instanceof Closure
            ? ($this->pseudonymizer)()
            : $this->pseudonymizer;

        return $this->resolved;
    }

    /**
     * Get an option value.
     */
    public function option(string $key, mixed $default = null): mixed
    {
        return $this->options[$key] ?? $default;
    }

    /**
     * Get an integer option, or the default.
     */
    public function intOption(string $key, int $default): int
    {
        $value = $this->options[$key] ?? null;

        return is_numeric($value) ? (int) $value : $default;
    }

    /**
     * Get a boolean option, or the default.
     */
    public function boolOption(string $key, bool $default): bool
    {
        $value = $this->options[$key] ?? null;

        return is_bool($value) ? $value : $default;
    }

    /**
     * Get a non-empty string option, or the default.
     */
    public function stringOption(string $key, string $default): string
    {
        $value = $this->options[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : $default;
    }

    /**
     * Create a copy of the context with the given options.
     *
     * @param  array<string, mixed>  $options
     */
    public function withOptions(array $options): self
    {
        return new self($this->replacement, $options, $this->pseudonymizer);
    }
}
