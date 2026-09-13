<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Recognition;

use Kirschbaum\Redactor\Recognition\Recognizers\PresidioRecognizer;

/**
 * Resolves a recogniser name from config to the thing that does the work.
 */
final class RecognizerRegistry
{
    /** @var array<string, Recognizer> */
    private array $recognizers = [];

    public function __construct()
    {
        $this->register(new PresidioRecognizer);
    }

    public function register(Recognizer $recognizer): void
    {
        $this->recognizers[$recognizer->name()] = $recognizer;
    }

    public function has(string $name): bool
    {
        return isset($this->recognizers[$name]);
    }

    public function get(string $name): ?Recognizer
    {
        return $this->recognizers[$name] ?? null;
    }

    /**
     * @return array<int, string>
     */
    public function names(): array
    {
        $names = array_keys($this->recognizers);
        sort($names);

        return $names;
    }
}
