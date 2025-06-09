<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\RedactionContext;

class LargeStringStrategy implements RedactionStrategyInterface
{
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        return is_string($value)
            && $context->config->maxValueLength !== null
            && strlen($value) > $context->config->maxValueLength;
    }

    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        $context->markRedacted();

        if (! is_string($value)) {
            return $value;
        }

        return sprintf('%s (String with %d characters)', $context->config->replacement, strlen($value));
    }
}
