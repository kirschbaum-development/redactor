<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Detection;

/**
 * The resolver that turns everything reported about one subject into the spans to rewrite.
 *
 * Detectors are deliberately naive, each reporting what it sees without
 * knowing what the others saw. Resolving that in one place means the same
 * rules apply whatever the competing spans came from, and a detector added
 * later slots in without learning anything about its neighbours.
 */
class DetectionSet
{
    /**
     * Apply the confidence floor, then resolve overlaps.
     *
     * Of two overlapping reports the higher score wins; on an equal score the
     * rule declared first wins, then the report that arrived first. Length is
     * deliberately not a criterion, since it would let a greedy general rule
     * swallow the precise one beside it.
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
                    || ($other->confidence->score === $candidate->confidence->score
                        && ($other->priority < $candidate->priority
                            || ($other->priority === $candidate->priority && $j < $i)));

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
