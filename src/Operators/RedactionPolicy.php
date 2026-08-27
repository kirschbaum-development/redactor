<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators;

use Kirschbaum\Redactor\Detection\Detection;
use Kirschbaum\Redactor\Patterns\PatternRule;

/**
 * Decides what happens to a detection.
 *
 * Precedence runs from most specific to least, so an override never has to
 * restate everything below it:
 *
 *   1. the location it was found at   (a path rule; beats everything)
 *   2. the kind of thing it is        (operators.email)
 *   3. the rule that found it         (the rule's own operator, or legacy mode)
 *   4. the profile default            (operators.default)
 *
 * Entity beating rule is deliberate. "Every email in this profile becomes a
 * surrogate" is a policy decision about data; which regex happened to spot it
 * is an implementation detail, and should not be able to override the policy.
 */
final readonly class RedactionPolicy
{
    /**
     * @param  array<string, OperatorSpec>  $byEntity  keyed by entity, plus 'default'
     */
    public function __construct(
        private array $byEntity = [],
        private OperatorSpec $default = new OperatorSpec(OperatorRegistry::REDACT),
    ) {}

    public function operatorFor(Detection $detection, ?PatternRule $rule = null, ?OperatorSpec $atLocation = null): OperatorSpec
    {
        if ($atLocation !== null) {
            return $atLocation;
        }

        if (isset($this->byEntity[$detection->entity])) {
            return $this->byEntity[$detection->entity];
        }

        if ($rule !== null && $rule->operator !== null) {
            return $rule->operator;
        }

        if (isset($this->byEntity['default'])) {
            return $rule?->operatorSpec() ?? $this->byEntity['default'];
        }

        return $rule?->operatorSpec() ?? $this->default;
    }

    public function defaultSpec(): OperatorSpec
    {
        return $this->byEntity['default'] ?? $this->default;
    }

    /**
     * @return array<int, string>
     */
    public function entities(): array
    {
        return array_values(array_filter(array_keys($this->byEntity), fn (string $k) => $k !== 'default'));
    }
}
