<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators\Surrogates;

use Kirschbaum\Redactor\Support\DeterministicRandom;

/**
 * Produces a stand-in that looks like the thing it replaces.
 *
 * Shape matters more than it first appears. A downstream log parser that
 * expects an email address, a fixed-width account number or a phone number will
 * break on "[REDACTED]" and carry on unbothered by a well-formed fake - so a
 * format-preserving surrogate is often the difference between a pipeline that
 * still works after redaction and one that quietly drops records.
 */
interface SurrogateGenerator
{
    public function supports(string $entity, string $value): bool;

    /**
     * @param  array<string, mixed>  $options
     */
    public function generate(string $value, DeterministicRandom $random, array $options = []): string;
}
