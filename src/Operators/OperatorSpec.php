<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators;

use InvalidArgumentException;

/**
 * A named operator plus its options, as configured.
 *
 * Accepts three spellings, because the right one depends on how much you are
 * saying:
 *
 *     'redact'                              // just the name
 *     ['partial' => ['keep' => 4]]          // name with options
 *     ['operator' => 'partial', 'keep' => 4]
 */
final readonly class OperatorSpec
{
    /**
     * @param  array<string, mixed>  $options
     */
    public function __construct(
        public string $name,
        public array $options = [],
    ) {}

    public static function parse(mixed $definition, string $path): self
    {
        if ($definition instanceof self) {
            return $definition;
        }

        if (is_string($definition)) {
            return new self($definition);
        }

        if (! is_array($definition) || $definition === []) {
            throw new InvalidArgumentException(sprintf(
                'Redactor config [%s] must name an operator.',
                $path
            ));
        }

        if (isset($definition['operator']) && is_string($definition['operator'])) {
            $options = $definition;
            unset($options['operator']);

            return new self($definition['operator'], self::stringKeyed($options));
        }

        // ['partial' => ['keep' => 4]] - a single name mapped to its options.
        $name = array_key_first($definition);

        if (! is_string($name)) {
            throw new InvalidArgumentException(sprintf(
                'Redactor config [%s] must name an operator.',
                $path
            ));
        }

        $options = $definition[$name];

        return new self($name, is_array($options) ? self::stringKeyed($options) : []);
    }

    /**
     * @param  array<mixed>  $options
     * @return array<string, mixed>
     */
    private static function stringKeyed(array $options): array
    {
        $out = [];

        foreach ($options as $key => $value) {
            $out[(string) $key] = $value;
        }

        return $out;
    }

    /**
     * @param  array<string, mixed>  $defaults
     */
    public function withDefaults(array $defaults): self
    {
        return new self($this->name, [...$defaults, ...$this->options]);
    }
}
