<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\Support\Pcre;

class RegexPatternsStrategy implements RedactionStrategyInterface
{
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        if (! is_string($value) || empty($context->config->patterns)) {
            return false;
        }

        foreach ($context->config->patterns as $rule => $pattern) {
            // onError: true. If the engine could not evaluate the pattern we do
            // not know the value is clean, so it is treated as sensitive.
            if (Pcre::matches($pattern, $value, onError: true, rule: (string) $rule)) {
                return true;
            }
        }

        return false;
    }

    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        $context->markRedacted();

        return $context->config->replacement;
    }
}
