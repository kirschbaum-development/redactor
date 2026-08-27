<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Support;

/**
 * A keyed, reproducible byte stream.
 *
 * Seeded from HMAC-SHA256 over (key, seed) in counter mode, so the same input
 * yields the same stream on any machine, in any process, forever - which is the
 * whole point of a pseudonym. It is deliberately not a general-purpose CSPRNG
 * and must never be used where unpredictability matters; here predictability is
 * the requirement.
 */
final class DeterministicRandom
{
    private string $buffer = '';

    private int $counter = 0;

    public function __construct(
        private readonly string $key,
        private readonly string $seed,
    ) {}

    public function byte(): int
    {
        if ($this->buffer === '') {
            $this->buffer = hash_hmac('sha256', $this->seed.'|'.$this->counter++, $this->key, true);
        }

        $byte = ord($this->buffer[0]);
        $this->buffer = substr($this->buffer, 1);

        return $byte;
    }

    /**
     * A value in [0, $bound) with rejection sampling, so the distribution is
     * not skewed by a modulo fold.
     */
    public function below(int $bound): int
    {
        if ($bound <= 1) {
            return 0;
        }

        // Draw enough bytes to cover the range, then reject anything landing in
        // the partial final window.
        $bytes = (int) ceil(log(max($bound, 2), 256));
        $max = 256 ** $bytes;
        $limit = $max - ($max % $bound);

        for ($attempt = 0; $attempt < 64; $attempt++) {
            $value = 0;
            for ($i = 0; $i < $bytes; $i++) {
                $value = ($value << 8) | $this->byte();
            }

            if ($value < $limit) {
                return $value % $bound;
            }
        }

        // Astronomically unlikely; fold rather than loop forever.
        return $value % $bound;
    }

    public function pick(string $alphabet): string
    {
        $length = strlen($alphabet);

        return $length === 0 ? '' : $alphabet[$this->below($length)];
    }

    public function digit(): string
    {
        return (string) $this->below(10);
    }

    public function token(int $length, string $alphabet = 'abcdefghijkmnopqrstuvwxyz23456789'): string
    {
        $out = '';
        for ($i = 0; $i < $length; $i++) {
            $out .= $this->pick($alphabet);
        }

        return $out;
    }
}
