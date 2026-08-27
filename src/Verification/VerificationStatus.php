<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Verification;

/**
 * Whether a detected credential is actually live.
 *
 * The distinction that matters is Active versus everything else. A scan of a
 * mature repository turns up hundreds of candidates - expired keys, examples in
 * docs, fixtures, rotated credentials - and a list that cannot separate the live
 * ones from the dead is a list nobody triages.
 */
enum VerificationStatus: string
{
    /** Confirmed working. Rotate it now. */
    case Active = 'active';

    /** The provider rejected it. Real shape, no longer a risk. */
    case Inactive = 'inactive';

    /** Not checked, or the check itself failed. Assume the worst. */
    case Unknown = 'unknown';

    public function isActive(): bool
    {
        return $this === self::Active;
    }

    /**
     * How urgent this makes the finding.
     *
     * Unknown deliberately ranks with Active rather than Inactive: a check that
     * could not complete is not evidence of safety, and treating it as such is
     * how a live key gets filtered out of a report.
     */
    public function severity(): string
    {
        return match ($this) {
            self::Active => 'critical',
            self::Unknown => 'high',
            self::Inactive => 'low',
        };
    }
}
