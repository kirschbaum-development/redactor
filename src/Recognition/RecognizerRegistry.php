<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Recognition;

use Kirschbaum\Redactor\Recognition\Recognizers\PresidioRecognizer;

/**
 * Resolves a recogniser name from config to the thing that does the work.
 */
class RecognizerRegistry
{
    /** @var array<string, Recognizer> */
    private array $recognizers = [];

    /**
     * Create a new recognizer registry instance.
     */
    public function __construct()
    {
        $this->register(new PresidioRecognizer);
    }

    /**
     * Register a recogniser under its own name.
     */
    public function register(Recognizer $recognizer): void
    {
        $this->recognizers[$recognizer->name()] = $recognizer;
    }

    /**
     * Determine if a recogniser is registered under the given name.
     */
    public function has(string $name): bool
    {
        return isset($this->recognizers[$name]);
    }

    /**
     * Get the recogniser registered under the given name, if any.
     */
    public function get(string $name): ?Recognizer
    {
        return $this->recognizers[$name] ?? null;
    }

    /**
     * Get the registered recogniser names.
     *
     * @return array<int, string>
     */
    public function names(): array
    {
        $names = array_keys($this->recognizers);
        sort($names);

        return $names;
    }
}
