<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Detection;

/**
 * How likely a detection is to be a real secret, and why.
 *
 * Binary matching forces a choice between noise and misses: the only way to
 * quiet a rule is to edit its regex, which usually means weakening it
 * everywhere. A score lets a consumer move one threshold instead, and the
 * signals behind it say what moving the threshold will cost.
 */
final readonly class Confidence
{
    public const CERTAIN = 1.0;

    public const HIGH = 0.9;

    public const MEDIUM = 0.6;

    public const LOW = 0.3;

    /**
     * @param  array<int, Signal>  $signals
     */
    private function __construct(
        public float $score,
        public array $signals = [],
    ) {}

    public static function of(float $score, string $reason = 'base rule confidence'): self
    {
        $clamped = self::clamp($score);

        return new self($clamped, [new Signal('base', $clamped, $reason)]);
    }

    /**
     * Add a contribution and re-derive the score.
     *
     * Deltas are applied to the remaining headroom rather than added flat, so
     * signals stack toward certainty without ever exceeding it and without one
     * strong signal swamping the rest.
     */
    public function with(string $name, float $delta, string $reason): self
    {
        $score = $delta >= 0.0
            ? $this->score + (1.0 - $this->score) * $delta
            : $this->score * (1.0 + $delta);

        return new self(
            self::clamp($score),
            [...$this->signals, new Signal($name, $delta, $reason)],
        );
    }

    public function meets(float $threshold): bool
    {
        return $this->score >= $threshold;
    }

    /**
     * @return array<int, string>
     */
    public function explain(): array
    {
        return array_map(fn (Signal $s) => $s->describe(), $this->signals);
    }

    public function label(): string
    {
        return match (true) {
            $this->score >= 0.9 => 'high',
            $this->score >= 0.6 => 'medium',
            $this->score >= 0.3 => 'low',
            default => 'very-low',
        };
    }

    private static function clamp(float $score): float
    {
        return max(0.0, min(1.0, $score));
    }
}
