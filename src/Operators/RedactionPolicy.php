<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators;

use Kirschbaum\Redactor\Detection\Detection;

/**
 * Decides what happens to a detection.
 *
 * Precedence runs from most specific to least: the location it was found at
 * (a path rule), the kind of thing it is (operators.email), the rule that
 * found it, then the profile default (operators.default). Entity beating rule
 * is deliberate: "every email becomes a surrogate" is a policy about data, and
 * which regex happened to spot it is an implementation detail.
 */
final readonly class RedactionPolicy
{
    /**
     * Create a new redaction policy instance.
     *
     * @param  array<string, OperatorSpec>  $byEntity  keyed by entity, plus 'default'
     */
    public function __construct(
        private array $byEntity = [],
        private OperatorSpec $default = new OperatorSpec(OperatorRegistry::REDACT),
    ) {}

    /**
     * Resolve the operator that applies to the given detection.
     */
    public function operatorFor(Detection $detection, ?OperatorSpec $atLocation = null): OperatorSpec
    {
        if ($atLocation !== null) {
            return $atLocation;
        }

        if (isset($this->byEntity[$detection->entity])) {
            return $this->byEntity[$detection->entity];
        }

        // Only a rule that actually chose an operator outranks the profile default,
        // since treating a rule's implied default as a choice would make
        // `operators.default` unreachable for anything found by a pattern...
        if ($detection->operator !== null) {
            return $detection->operator;
        }

        return $this->byEntity['default'] ?? $this->default;
    }

    /**
     * Get the profile's default operator.
     */
    public function defaultSpec(): OperatorSpec
    {
        return $this->byEntity['default'] ?? $this->default;
    }

    /**
     * Get the entities with a configured operator.
     *
     * @return array<int, string>
     */
    public function entities(): array
    {
        return array_values(array_filter(array_keys($this->byEntity), fn (string $k) => $k !== 'default'));
    }
}
