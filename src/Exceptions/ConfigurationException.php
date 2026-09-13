<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Exceptions;

use InvalidArgumentException;

/**
 * A profile or a rule is misconfigured. The message names the config path.
 */
class ConfigurationException extends InvalidArgumentException implements RedactorException {}
