<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Exceptions;

use RuntimeException;

/**
 * Git could not answer the scanner: not a repository, or a command failed.
 */
class GitException extends RuntimeException implements RedactorException {}
