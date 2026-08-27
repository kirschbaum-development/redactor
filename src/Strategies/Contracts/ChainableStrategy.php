<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies\Contracts;

/**
 * Marks a strategy that transforms a value in place rather than replacing it.
 *
 * The redactor stops at the first strategy that handles a value, which is
 * correct when handling means "this whole value is gone". A strategy that
 * redacts spans inside a string leaves the rest of the string standing, so the
 * remaining strategies still need a look at it: an entropy-detectable secret
 * sitting next to an email address must not survive just because the email
 * matched first.
 */
interface ChainableStrategy {}
