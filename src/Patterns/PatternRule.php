<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Patterns;

use InvalidArgumentException;
use Kirschbaum\Redactor\Config\ConfigValue;
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
    ) {}

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

        if ($maskCharacter === '') {
            $maskCharacter = '*';
        }

        return new self(
            name: $name,
            pattern: $pattern,
            mode: $mode,
            keep: $keep,
            maskCharacter: mb_substr($maskCharacter, 0, 1),
        );
    }

    /**
     * Whether this rule replaces the entire value rather than the match.
     */
    public function replacesWholeValue(): bool
    {
        return $this->mode === self::MODE_FULL;
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
