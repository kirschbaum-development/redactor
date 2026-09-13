<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators\Surrogates;

use Kirschbaum\Redactor\Support\DeterministicRandom;

/**
 * Picks the most specific surrogate generator that can handle a value.
 *
 * The first generator that claims the value wins, and CharacterClassSurrogate
 * claims everything, so it is the fallback rather than a list entry.
 * Applications can register their own ahead of the built-ins for domain types
 * the package has never heard of: a policy number, an NHS number, an internal
 * account format.
 */
class SurrogateFactory
{
    /** @var array<int, SurrogateGenerator> */
    private array $generators;

    /** Supports everything, so it answers whenever nothing more specific does. */
    private readonly CharacterClassSurrogate $fallback;

    /**
     * Create a new surrogate factory instance.
     *
     * @param  array<int, SurrogateGenerator>  $custom
     */
    public function __construct(array $custom = [])
    {
        $this->generators = [
            ...$custom,
            new EmailSurrogate,
            new CreditCardSurrogate,
        ];
        $this->fallback = new CharacterClassSurrogate;
    }

    /**
     * Register a generator ahead of the built-in ones.
     */
    public function register(SurrogateGenerator $generator): void
    {
        array_unshift($this->generators, $generator);
    }

    /**
     * Generate a surrogate using the first generator that supports the value.
     *
     * @param  array<string, mixed>  $options
     */
    public function generate(string $entity, string $value, DeterministicRandom $random, array $options = []): string
    {
        foreach ($this->generators as $generator) {
            if ($generator->supports($entity, $value)) {
                return $generator->generate($value, $random, $options);
            }
        }

        // Nothing more specific claimed it, so keep its shape and nothing else...
        return $this->fallback->generate($value, $random, $options);
    }
}
