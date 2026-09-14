<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies\Contracts;

/**
 * Marks a strategy that transforms a value in place rather than replacing it.
 *
 * The redactor stops at the first strategy that handles a value, which is right
 * when handling means the whole value is gone. A strategy that redacts spans
 * inside a string leaves the rest standing, so the remaining strategies still
 * need to see it: a secret beside an email address must not survive because
 * the email matched first.
 */
interface ChainableStrategy {}
