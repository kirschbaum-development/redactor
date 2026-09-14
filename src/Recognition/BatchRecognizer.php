<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Recognition;

/**
 * A recogniser that can read many texts in one call.
 *
 * A model behind a network costs a round trip per call and almost nothing per
 * extra byte, so a payload with fifty prose fields should cost one call, not
 * fifty. A recogniser that can take a list implements this; one that cannot
 * is simply asked once per text.
 */
interface BatchRecognizer extends Recognizer
{
    /**
     * Recognise entities in each of the given texts.
     *
     * @param  array<int, string>  $texts
     * @param  array<int, string>  $entities  the recogniser's own labels to look for; empty means all
     * @return array<int, array<int, RecognizedSpan>> spans per input index, offsets relative to that text
     *
     * @throws \Throwable when the recogniser could not answer
     */
    public function recognizeMany(array $texts, string $language, array $entities, float $scoreThreshold): array;
}
