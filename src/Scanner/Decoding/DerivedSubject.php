<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Scanner\Decoding;

/**
 * Text recovered from an encoded span of the original, scanned in its own
 * right and reported at the span it came from.
 */
final readonly class DerivedSubject
{
    public function __construct(
        /** The decoded text to scan. */
        public string $text,
        /** Byte offset of the encoded span in the original window. */
        public int $offset,
        /** Byte length of the encoded span in the original window. */
        public int $length,
        /** base64, url or json. */
        public string $encoding,
    ) {}
}
