<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Patterns;

use Kirschbaum\Redactor\Config\ConfigValue;
use Kirschbaum\Redactor\Detection\Confidence;
use Kirschbaum\Redactor\Exceptions\ConfigurationException;
use Kirschbaum\Redactor\Operators\OperatorRegistry;
use Kirschbaum\Redactor\Operators\OperatorSpec;
use Kirschbaum\Redactor\Support\AllowList;
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

    /**
     * Create a new pattern rule instance.
     *
     * @param  array<int, string>  $keywords
     * @param  array<int, string>  $samples
     * @param  array<int, string>  $counterSamples
     */
    public function __construct(
        public string $name,
        public string $pattern,
        public string $mode = self::MODE_REPLACE,
        public int $keep = 4,
        public string $maskCharacter = '*',
        /** The capture group holding the secret, or 0 for the whole match, so a labelled value keeps its label. */
        public int $capture = 0,
        /** The structural check the matched text must pass, or null when shape is enough. */
        public ?string $validator = null,
        /** The kind of thing this rule finds, defaulting to the rule name. */
        public ?string $entity = null,
        /** How much to trust a bare match, before validators and context adjust it. */
        public float $confidence = Confidence::MEDIUM,
        /** What to do with what it finds, or null to let the profile decide. */
        public ?OperatorSpec $operator = null,
        /** Lowercased literals at least one of which must appear in the subject before the pattern is tried. */
        public array $keywords = [],
        /** Matches this rule alone should let through, scoped to the rule unlike the profile allowlist. */
        public ?AllowList $allow = null,
        /** The shortest text this pattern can match, in bytes; never above the true minimum or matches are missed. */
        public int $minLength = 1,
        /** Texts this rule must detect something in, checked by redactor:validate. */
        public array $samples = [],
        /** Texts this rule must not detect anything in. */
        public array $counterSamples = [],
    ) {}

    /**
     * Get the entity this rule detects.
     */
    public function entity(): string
    {
        return $this->entity ?? $this->name;
    }

    /**
     * Determine if this rule actually asked for a particular operator.
     *
     * `mode` defaults to replace, so operatorSpec() can always produce
     * something, which is not the same as the rule having chosen it. Without
     * this distinction a rule with no preference would still outrank the
     * profile's `operators.default`, making that setting unreachable.
     */
    public function hasExplicitOperator(): bool
    {
        return $this->operator !== null || $this->mode !== self::MODE_REPLACE;
    }

    /**
     * Get the operator this rule asks for, translating the legacy `mode` when none is set.
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
     * An uncompilable pattern is dropped rather than fatal; a malformed rule,
     * such as a bad mode or a missing pattern, is a config error and throws.
     *
     * @throws ConfigurationException
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

        // A dictionary rule compiles a list of words into one alternation, for names no regex could express...
        if ($pattern === null && isset($definition['words'])) {
            $words = array_values(array_filter(
                ConfigValue::stringList($definition['words'], $path.'.words'),
                fn (string $word) => trim($word) !== ''
            ));

            if ($words === []) {
                throw new ConfigurationException(sprintf(
                    'Redactor config [%s] lists no words.',
                    $path
                ));
            }

            usort($words, fn (string $a, string $b) => strlen($b) <=> strlen($a));

            $pattern = '/(?<![\p{L}\p{N}])(?:'
                .implode('|', array_map(fn (string $word) => preg_quote(trim($word), '/'), $words))
                .')(?![\p{L}\p{N}])/iu';
        }

        if (! is_string($pattern)) {
            throw new ConfigurationException(sprintf(
                'Redactor config [%s] must define a "pattern" string or a "words" list.',
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

        $keywords = array_values(array_filter(array_map(
            'strtolower',
            ConfigValue::stringList($definition['keywords'] ?? [], $path.'.keywords')
        ), fn (string $keyword) => $keyword !== ''));

        $allow = ConfigValue::stringList($definition['allow'] ?? [], $path.'.allow');

        $minLength = ConfigValue::positiveInt($definition['min_length'] ?? 1, 1, $path.'.min_length');
        $samples = ConfigValue::stringList($definition['samples'] ?? [], $path.'.samples');
        $counterSamples = ConfigValue::stringList($definition['counter_samples'] ?? [], $path.'.counter_samples');

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
            keywords: $keywords,
            allow: $allow === [] ? null : AllowList::for($allow),
            minLength: $minLength,
            samples: $samples,
            counterSamples: $counterSamples,
        );
    }

    /**
     * Determine if the matched text passes this rule's allow list and structural check.
     */
    public function accepts(string $match): bool
    {
        if ($this->allow !== null && $this->allow->allows($match)) {
            return false;
        }

        return $this->validator === null || Validator::passes($this->validator, $match);
    }

    /**
     * Determine if this rule replaces the entire value rather than the match.
     */
    public function replacesWholeValue(): bool
    {
        return $this->mode === self::MODE_FULL;
    }

    /**
     * Rewrite one match, substituting only the capture group when the rule names one.
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

        // An optional group that did not participate reports offset -1...
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
     * Get the text that stands in for one matched span.
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
     * Mask everything but the trailing characters.
     */
    private function partial(string $match): string
    {
        $length = mb_strlen($match);

        if ($length <= $this->keep) {
            // Too short to reveal any of it without revealing all of it...
            return str_repeat($this->maskCharacter, max(1, $length));
        }

        return str_repeat($this->maskCharacter, $length - $this->keep)
            .mb_substr($match, -$this->keep);
    }
}
