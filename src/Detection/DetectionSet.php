<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Detection;

/**
 * Turns everything the detectors reported about one subject into the spans
 * that will actually be rewritten.
 *
 * Detectors are deliberately naive: each reports what it sees without knowing
 * what the others saw. Resolving that in one place means the same rules apply
 * whether the competing spans came from two regexes, a regex and the entropy
 * detector, or a recogniser model - and that a detector added later slots in
 * without learning anything about its neighbours.
 */
final class DetectionSet
{
    /**
     * Apply the confidence floor, then resolve overlaps.
     *
     * Of two overlapping reports the higher score wins: a Luhn-validated card
     * outranks the bare digit run that also matched it. On an equal score the
     * one reported first wins, which is the rule listed first in the profile -
     * so `url_with_auth` declared ahead of `email` takes the password out of
     * `https://user:pass@host` and leaves the host, exactly as the config
     * comments promise. Length is deliberately not a criterion: it would let a
     * greedy general rule swallow the precise one beside it.
     *
     * @param  array<int, Detection>  $detections
     * @return array<int, Detection> non-overlapping, ordered by offset
     */
    public static function resolve(array $detections, float $minConfidence = 0.0): array
    {
        $candidates = array_values(array_filter(
            $detections,
            fn (Detection $d) => $d->value !== '' && ($d->failClosed || $d->confidence->meets($minConfidence))
        ));

        if (count($candidates) < 2) {
            return $candidates;
        }

        $kept = [];

        foreach ($candidates as $i => $candidate) {
            $beaten = false;

            foreach ($candidates as $j => $other) {
                if ($i === $j || ! $candidate->overlaps($other)) {
                    continue;
                }

                $otherWins = $other->confidence->score > $candidate->confidence->score
                    || ($other->confidence->score === $candidate->confidence->score && $j < $i);

                if ($otherWins) {
                    $beaten = true;
                    break;
                }
            }

            if (! $beaten) {
                $kept[] = $candidate;
            }
        }

        usort($kept, fn (Detection $a, Detection $b) => $a->offset <=> $b->offset);

        return $kept;
    }
}
