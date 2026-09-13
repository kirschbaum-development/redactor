<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Tokenization;

/**
 * Puts original values back where tokens stand.
 *
 * Walks strings, arrays and Arrayable-shaped nesting and resolves every token
 * the store knows; a token it does not know - expired, from another
 * application, invented by a model - is left exactly as it is, since
 * guessing would be worse than leaving it.
 */
class Detokenizer
{
    public function __construct(
        private readonly TokenStore $store,
        private readonly string $prefix = TokenizeOperator::PREFIX,
    ) {}

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
     * Every token in a string, whether or not the store knows it.
     *
     * @return array<int, string>
     */
    public function tokensIn(string $text): array
    {
        preg_match_all($this->pattern(), $text, $matches);

        return array_values(array_unique($matches[0]));
    }

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

    private function pattern(): string
    {
        return '/\b'.preg_quote($this->prefix, '/').'_[a-z0-9]+(?:_[a-z0-9]+)*_[a-z0-9]{'.TokenizeOperator::ID_LENGTH.'}\b/';
    }
}
