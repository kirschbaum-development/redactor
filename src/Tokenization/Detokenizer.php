<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Tokenization;

/**
 * Puts original values back where tokens stand.
 *
 * Walks strings and arrays and resolves every token the store knows; a token
 * it does not know, whether expired, from another application or invented by
 * a model, is left exactly as it is, since guessing would be worse.
 */
class Detokenizer
{
    /**
     * Create a new detokenizer instance.
     */
    public function __construct(
        private readonly TokenStore $store,
        private readonly string $prefix = TokenizeOperator::PREFIX,
    ) {}

    /**
     * Replace every known token in the content with its original value.
     */
    public function detokenize(mixed $content): mixed
    {
        if (is_string($content)) {
            return $this->replaceIn($content);
        }

        if (is_array($content)) {
            $out = [];

            foreach ($content as $key => $value) {
                $out[$key] = $this->detokenize($value);
            }

            return $out;
        }

        return $content;
    }

    /**
     * Get every token in a string, whether or not the store knows it.
     *
     * @return array<int, string>
     */
    public function tokensIn(string $text): array
    {
        preg_match_all($this->pattern(), $text, $matches);

        return array_values(array_unique($matches[0]));
    }

    /**
     * Replace every known token in a string.
     */
    private function replaceIn(string $text): string
    {
        if (! str_contains($text, $this->prefix.'_')) {
            return $text;
        }

        $result = preg_replace_callback($this->pattern(), function (array $m): string {
            return $this->store->get($m[0]) ?? $m[0];
        }, $text);

        return $result ?? $text;
    }

    /**
     * Get the pattern that matches a token.
     */
    private function pattern(): string
    {
        return '/\b'.preg_quote($this->prefix, '/').'_[a-z0-9]+(?:_[a-z0-9]+)*_[a-z0-9]{'.TokenizeOperator::ID_LENGTH.'}\b/';
    }
}
