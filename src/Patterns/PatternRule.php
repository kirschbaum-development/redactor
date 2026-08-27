<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Patterns;

use InvalidArgumentException;
use Kirschbaum\Redactor\Config\ConfigValue;
use Kirschbaum\Redactor\Detection\Confidence;
use Kirschbaum\Redactor\Operators\OperatorRegistry;
use Kirschbaum\Redactor\Operators\OperatorSpec;
use Kirschbaum\Redactor\Support\Pcre;

/**
 * One detection pattern plus what to do with the text it matches.
 *
 * Configure either as a shorthand string:
 *
 *     'email' => '/[^@\s]+@[^@\s]+/',
 *
 * or as a full rule:
 *
 *     'credit_card' => [
 *         'pattern' => '/\b(?:\d[ -]*?){13,16}\b/',
 *         'mode'    => 'partial',
 *         'keep'    => 4,
 *     ],
 */
final readonly class PatternRule
{
    /** Replace just the matched text with the replacement string. */
    public const MODE_REPLACE = 'replace';

    /** Replace each matched character with a mask character, preserving length. */
    public const MODE_MASK = 'mask';

    /** Keep the last N characters of the match and mask the rest. */
    public const MODE_PARTIAL = 'partial';

    /** Delete the matched text entirely. */
    public const MODE_REMOVE = 'remove';

    /** Replace the whole value, not just the match. The pre-1.0 behaviour. */
    public const MODE_FULL = 'full';

    /** @var array<int, string> */
    public const MODES = [
        self::MODE_REPLACE,
        self::MODE_MASK,
        self::MODE_PARTIAL,
        self::MODE_REMOVE,
        self::MODE_FULL,
    ];

    public function __construct(
        public string $name,
        public string $pattern,
        public string $mode = self::MODE_REPLACE,
        public int $keep = 4,
        public string $maskCharacter = '*',
        /**
         * Which capture group holds the secret.
         *
         * 0 means the whole match. Use a group when the pattern needs
         * surrounding context to match confidently but that context is not
         * itself sensitive - "aws_secret_access_key = <40 chars>" should keep
         * its label and lose only the value.
         */
        public int $capture = 0,
        /**
         * Structural check the matched text must pass to count as a finding.
         *
         * A regex asserts shape only; a validator asserts that the value could
         * actually be what the pattern claims. Null means shape is enough.
         */
        public ?string $validator = null,
        /**
         * What kind of thing this rule finds.
         *
         * Drives surrogate selection and per-entity policy; defaults to the
         * rule name, which is right most of the time ('email' finds an email).
         */
        public ?string $entity = null,
        /**
         * How much to trust a bare match from this pattern, before validators
         * and context adjust it.
         */
        public float $confidence = Confidence::MEDIUM,
        /**
         * What to do with what it finds. Null means the profile decides.
         */
        public ?OperatorSpec $operator = null,
    ) {}

    /**
     * The entity this rule detects.
     */
    public function entity(): string
    {
        return $this->entity ?? $this->name;
    }

    /**
     * The operator this rule asks for, translating the legacy `mode` when no
     * explicit operator is set.
     */
    public function operatorSpec(): OperatorSpec
    {
        if ($this->operator !== null) {
            return $this->operator;
        }

        return new OperatorSpec(
            match ($this->mode) {
                self::MODE_MASK => OperatorRegistry::MASK,
                self::MODE_PARTIAL => OperatorRegistry::PARTIAL,
                self::MODE_REMOVE => OperatorRegistry::REMOVE,
                default => OperatorRegistry::REDACT,
            },
            ['keep' => $this->keep, 'mask_character' => $this->maskCharacter],
        );
    }

    /**
     * Build a rule from its configured form, or return null if unusable.
     *
     * An uncompilable pattern is dropped rather than fatal, matching the
     * previous behaviour of validatePatterns(); a malformed *rule* (bad mode,
     * missing pattern) is a config error and throws.
     */
    public static function fromConfig(string $name, mixed $definition, string $path): ?self
    {
        if (is_string($definition)) {
            return Pcre::isValidPattern($definition)
                ? new self(name: $name, pattern: $definition)
                : null;
        }

        if (! is_array($definition)) {
            return null;
        }

        $pattern = $definition['pattern'] ?? null;

        if (! is_string($pattern)) {
            throw new InvalidArgumentException(sprintf(
                'Redactor config [%s] must define a "pattern" string.',
                $path
            ));
        }

        if (! Pcre::isValidPattern($pattern)) {
            return null;
        }

        $mode = ConfigValue::enum($definition['mode'] ?? self::MODE_REPLACE, self::MODES, self::MODE_REPLACE, $path.'.mode');
        $keep = ConfigValue::positiveInt($definition['keep'] ?? 4, 4, $path.'.keep');
        $maskCharacter = ConfigValue::string($definition['mask_character'] ?? '*', '*', $path.'.mask_character');
        $validator = $definition['validator'] ?? null;
        $validator = $validator === null
            ? null
            : ConfigValue::enum($validator, Validator::NAMES, Validator::LUHN, $path.'.validator');

        $entity = $definition['entity'] ?? null;
        $entity = is_string($entity) && $entity !== '' ? $entity : null;

        $confidence = $definition['confidence'] ?? Confidence::MEDIUM;
        $confidence = is_numeric($confidence)
            ? max(0.0, min(1.0, (float) $confidence))
            : Confidence::MEDIUM;

        $operator = isset($definition['operator'])
            ? OperatorSpec::parse($definition['operator'], $path.'.operator')
            : null;

        $capture = $definition['capture'] ?? 0;
        $capture = $capture === 0 || $capture === '0'
            ? 0
            : ConfigValue::positiveInt($capture, 0, $path.'.capture');

        if ($maskCharacter === '') {
            $maskCharacter = '*';
        }

        return new self(
            name: $name,
            pattern: $pattern,
            mode: $mode,
            keep: $keep,
            maskCharacter: mb_substr($maskCharacter, 0, 1),
            capture: $capture,
            validator: $validator,
            entity: $entity,
            confidence: $confidence,
            operator: $operator,
        );
    }

    /**
     * Whether the matched text passes this rule's structural check.
     */
    public function accepts(string $match): bool
    {
        return $this->validator === null || Validator::passes($this->validator, $match);
    }

    /**
     * Whether this rule replaces the entire value rather than the match.
     */
    public function replacesWholeValue(): bool
    {
        return $this->mode === self::MODE_FULL;
    }

    /**
     * Rewrite one match, substituting only the capture group when the rule
     * names one, so the surrounding context the pattern needed survives.
     *
     * @param  array<int|string, array{0: string, 1: int}>  $matches  offset-capture matches
     */
    public function rewriteMatch(array $matches, string $replacement): string
    {
        [$full, $fullOffset] = $matches[0];

        if ($this->capture === 0 || ! isset($matches[$this->capture])) {
            return $this->accepts($full) ? $this->substitute($full, $replacement) : $full;
        }

        [$group, $groupOffset] = $matches[$this->capture];

        // An optional group that did not participate reports offset -1.
        if ($groupOffset < 0 || $group === '') {
            return $this->accepts($full) ? $this->substitute($full, $replacement) : $full;
        }

        if (! $this->accepts($group)) {
            return $full;
        }

        $relative = $groupOffset - $fullOffset;

        return substr($full, 0, $relative)
            .$this->substitute($group, $replacement)
            .substr($full, $relative + strlen($group));
    }

    /**
     * Produce the text that should stand in for one matched span.
     */
    public function substitute(string $match, string $replacement): string
    {
        return match ($this->mode) {
            self::MODE_REMOVE => '',
            self::MODE_MASK => str_repeat($this->maskCharacter, max(1, mb_strlen($match))),
            self::MODE_PARTIAL => $this->partial($match),
            default => $replacement,
        };
    }

    /**
     * Mask everything but the trailing characters, so a value stays
     * recognisable to a human reading a log without being usable.
     */
    private function partial(string $match): string
    {
        $length = mb_strlen($match);

        if ($length <= $this->keep) {
            // Too short to reveal any of it without revealing all of it.
            return str_repeat($this->maskCharacter, max(1, $length));
        }

        return str_repeat($this->maskCharacter, $length - $this->keep)
            .mb_substr($match, -$this->keep);
    }
}
