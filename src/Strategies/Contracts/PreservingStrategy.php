<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies\Contracts;

/**
 * Marks a strategy that declares a value safe rather than redacting it.
 *
 * A preserving strategy ends the chain and stops the walk: the value it
 * approves is emitted exactly as it arrived, including everything nested
 * beneath it. That is a deliberate, load-bearing promise - "this key is safe"
 * has to mean the same thing for a scalar and for the array under it, or the
 * setting means nothing predictable at all.
 *
 * The corollary is that a safe key must be a key that structurally cannot
 * carry sensitive data. A free-text field is not one, however ordinary its
 * name.
 */
interface PreservingStrategy {}
