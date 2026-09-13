<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators;

use Kirschbaum\Redactor\Exceptions\ConfigurationException;

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
     * Create a new operator spec instance.
     *
     * @param  array<string, mixed>  $options
     */
    public function __construct(
        public string $name,
        public array $options = [],
    ) {}

    /**
     * Parse an operator definition from its configured form.
     *
     * @throws ConfigurationException
     */
    public static function parse(mixed $definition, string $path): self
    {
        if ($definition instanceof self) {
            return $definition;
        }

        if (is_string($definition)) {
            return new self($definition);
        }

        if (! is_array($definition) || $definition === []) {
            throw new ConfigurationException(sprintf(
                'Redactor config [%s] must name an operator.',
                $path
            ));
        }

        if (isset($definition['operator']) && is_string($definition['operator'])) {
            $options = $definition;
            unset($options['operator']);

            return new self($definition['operator'], self::stringKeyed($options));
        }

        // A single name mapped to its options, as in ['partial' => ['keep' => 4]]...
        $name = array_key_first($definition);

        if (! is_string($name)) {
            throw new ConfigurationException(sprintf(
                'Redactor config [%s] must name an operator.',
                $path
            ));
        }

        $options = $definition[$name];

        return new self($name, is_array($options) ? self::stringKeyed($options) : []);
    }

    /**
     * Cast every option key to a string.
     *
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
     * Create a copy of the spec with the given defaults beneath its options.
     *
     * @param  array<string, mixed>  $defaults
     */
    public function withDefaults(array $defaults): self
    {
        return new self($this->name, [...$defaults, ...$this->options]);
    }
}
