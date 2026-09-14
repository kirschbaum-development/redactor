<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Exceptions;

use InvalidArgumentException;

/**
 * The exception thrown when a profile or a rule is misconfigured; the message names the config path.
 */
class ConfigurationException extends InvalidArgumentException implements RedactorException {}
