<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Exceptions;

class ProfileNotFoundException extends ConfigurationException
{
    public static function named(string $profile): self
    {
        return new self("Redaction profile [{$profile}] is not configured.");
    }
}
