<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor;

use Illuminate\Contracts\Support\Arrayable;
use JsonSerializable;
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
/**
 * @implements Arrayable<string, mixed>
 */
final readonly class RedactionResult implements Arrayable, JsonSerializable
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

    /**
     * Get the result as an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'value' => $this->value,
            'was_redacted' => $this->wasRedacted,
            'redacted_keys' => $this->redactedKeys,
            'findings' => array_map(fn (MatchFinding $finding) => $finding->toArray(), $this->findings),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
