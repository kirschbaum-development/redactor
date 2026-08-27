<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor;

use Kirschbaum\Redactor\Findings\MatchFinding;

/**
 * The outcome of a redaction, with its metadata alongside the value rather
 * than injected into it.
 *
 * The `_redacted` / `_redacted_keys` markers write the redactor's bookkeeping
 * into the caller's own array, which turns a JSON list into an object and can
 * overwrite a key the caller actually uses. Prefer this:
 *
 *     $result = Redactor::redactWithMetadata($payload);
 *     $result->value;         // the redacted payload, untouched otherwise
 *     $result->wasRedacted;   // whether anything matched
 *     $result->redactedKeys;  // which keys were affected
 */
final readonly class RedactionResult
{
    /**
     * @param  array<int, string>  $redactedKeys
     * @param  array<int, MatchFinding>  $findings
     */
    public function __construct(
        public mixed $value,
        public bool $wasRedacted,
        public array $redactedKeys = [],
        public array $findings = [],
    ) {}
}
