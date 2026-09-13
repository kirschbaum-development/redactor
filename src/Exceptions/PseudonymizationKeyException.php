<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Exceptions;

use RuntimeException;

/**
 * No key strong enough to pseudonymise with could be produced.
 */
class PseudonymizationKeyException extends RuntimeException implements RedactorException {}
