<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators\Surrogates;

use Kirschbaum\Redactor\Support\DeterministicRandom;

/**
 * Picks the most specific surrogate generator that can handle a value.
 *
 * Order is significance, not preference: the first generator that claims the
 * value wins, and CharacterClassSurrogate claims everything, so it must stay
 * last. Applications can register their own ahead of the built-ins for domain
 * types the package has never heard of - a policy number, an NHS number, an
 * internal account format.
 */
final class SurrogateFactory
{
    /** @var array<int, SurrogateGenerator> */
    private array $generators;

    /**
     * @param  array<int, SurrogateGenerator>  $custom
     */
    public function __construct(array $custom = [])
    {
        $this->generators = [
            ...$custom,
            new EmailSurrogate,
            new CreditCardSurrogate,
            // Always last: it supports everything.
            new CharacterClassSurrogate,
        ];
    }

    public function register(SurrogateGenerator $generator): void
    {
        array_unshift($this->generators, $generator);
    }

    /**
     * @param  array<string, mixed>  $options
     */
    public function generate(string $entity, string $value, DeterministicRandom $random, array $options = []): string
    {
        foreach ($this->generators as $generator) {
            if ($generator->supports($entity, $value)) {
                return $generator->generate($value, $random, $options);
            }
        }

        return (new CharacterClassSurrogate)->generate($value, $random, $options);
    }
}
