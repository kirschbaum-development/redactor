<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators;

use InvalidArgumentException;
use Kirschbaum\Redactor\Operators\Surrogates\SurrogateFactory;

/**
 * Resolves an operator name to the thing that does the work.
 *
 * Applications register their own here - `tokenize` against a vault, `encrypt`
 * with a reversible cipher, `classify` into a bucket - and use them from config
 * by name, without touching detection.
 */
final class OperatorRegistry
{
    public const REDACT = 'redact';

    public const MASK = 'mask';

    public const PARTIAL = 'partial';

    public const REMOVE = 'remove';

    public const PRESERVE = 'preserve';

    public const HASH = 'hash';

    public const SURROGATE = 'surrogate';

    /** @var array<string, Operator> */
    private array $operators;

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
        ];
    }

    public function register(string $name, Operator $operator): void
    {
        $this->operators[$name] = $operator;
    }

    public function has(string $name): bool
    {
        return isset($this->operators[$name]);
    }

    public function get(string $name): Operator
    {
        return $this->operators[$name] ?? throw new InvalidArgumentException(sprintf(
            'Unknown redaction operator [%s]. Available: %s.',
            $name,
            implode(', ', $this->names())
        ));
    }

    /**
     * @return array<int, string>
     */
    public function names(): array
    {
        $names = array_keys($this->operators);
        sort($names);

        return $names;
    }
}
