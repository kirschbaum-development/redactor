<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators;

use Kirschbaum\Redactor\Exceptions\ConfigurationException;
use Kirschbaum\Redactor\Operators\Surrogates\SurrogateFactory;

/**
 * Resolves an operator name to the thing that does the work.
 *
 * Applications register their own here, `tokenize` against a vault, `encrypt`
 * with a reversible cipher, `classify` into a bucket, and use them from config
 * by name, without touching detection.
 */
class OperatorRegistry
{
    public const REDACT = 'redact';

    public const MASK = 'mask';

    public const PARTIAL = 'partial';

    public const REMOVE = 'remove';

    public const PRESERVE = 'preserve';

    public const HASH = 'hash';

    public const SURROGATE = 'surrogate';

    public const NULLIFY = 'nullify';

    /** @var array<string, Operator> */
    private array $operators;

    /**
     * Create a new operator registry instance.
     */
    public function __construct(?SurrogateFactory $surrogates = null)
    {
        $this->operators = [
            self::REDACT => new RedactOperator,
            self::MASK => new MaskOperator,
            self::PARTIAL => new PartialOperator,
            self::REMOVE => new RemoveOperator,
            self::PRESERVE => new PreserveOperator,
            self::HASH => new HashOperator,
            self::SURROGATE => new SurrogateOperator($surrogates ?? new SurrogateFactory),
            self::NULLIFY => new NullifyOperator,
        ];
    }

    /**
     * Register an operator under the given name.
     */
    public function register(string $name, Operator $operator): void
    {
        $this->operators[$name] = $operator;
    }

    /**
     * Determine if an operator is registered under the given name.
     */
    public function has(string $name): bool
    {
        return isset($this->operators[$name]);
    }

    /**
     * Get the operator registered under the given name.
     *
     * @throws ConfigurationException
     */
    public function get(string $name): Operator
    {
        return $this->operators[$name] ?? throw new ConfigurationException(sprintf(
            'Unknown redaction operator [%s]. Available: %s.',
            $name,
            implode(', ', $this->names())
        ));
    }

    /**
     * Get the registered operator names.
     *
     * @return array<int, string>
     */
    public function names(): array
    {
        $names = array_keys($this->operators);
        sort($names);

        return $names;
    }
}
