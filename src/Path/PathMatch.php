<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Path;

use Kirschbaum\Redactor\Operators\OperatorSpec;

/**
 * A path rule that fired, and which one it was.
 *
 * The source pattern travels with the match so a finding can say *why* a value
 * was rewritten - "matched request.headers.*" is actionable, "it was redacted"
 * is not.
 */
final readonly class PathMatch
{
    public function __construct(
        public OperatorSpec $spec,
        public string $pattern,
        public int $specificity,
    ) {}
}
