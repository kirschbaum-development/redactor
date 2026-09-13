<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies\Contracts;

/**
 * Marks a strategy that reports detections instead of rewriting the value.
 *
 * Its handle() returns the value untouched and leaves what it found on the
 * context. Consecutive detecting strategies all see the same original string
 * and the context rewrites it once after the last of them, so a surrogate
 * written by one is never re-detected by the next and every offset points into
 * the value the caller passed.
 */
interface DetectingStrategy extends ChainableStrategy {}
