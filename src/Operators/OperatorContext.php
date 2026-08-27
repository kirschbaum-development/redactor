<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators;

use Kirschbaum\Redactor\Support\Pseudonymizer;

/**
 * Everything an operator is allowed to know.
 *
 * Deliberately narrow: operators receive the replacement string, their own
 * options and the pseudonymizer, and nothing else. They cannot reach the
 * payload, the profile or the container, which keeps them pure enough to test
 * in isolation and impossible to turn into a second detection layer.
 */
final readonly class OperatorContext
{
    /**
     * @param  array<string, mixed>  $options
     */
    public function __construct(
        public string $replacement,
        public array $options = [],
        public ?Pseudonymizer $pseudonymizer = null,
    ) {}

    public function option(string $key, mixed $default = null): mixed
    {
        return $this->options[$key] ?? $default;
    }

    public function intOption(string $key, int $default): int
    {
        $value = $this->options[$key] ?? null;

        return is_numeric($value) ? (int) $value : $default;
    }

    public function boolOption(string $key, bool $default): bool
    {
        $value = $this->options[$key] ?? null;

        return is_bool($value) ? $value : $default;
    }

    public function stringOption(string $key, string $default): string
    {
        $value = $this->options[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : $default;
    }

    /**
     * @param  array<string, mixed>  $options
     */
    public function withOptions(array $options): self
    {
        return new self($this->replacement, $options, $this->pseudonymizer);
    }
}
