<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor;

use Kirschbaum\Redactor\Support\InternalLog;
use Kirschbaum\Redactor\Support\Pseudonymizer;
use Throwable;

/**
 * The factory that builds a profile's pseudonymizer, or logs why it could not.
 *
 * Key handling is the whole security surface of pseudonymisation, so it has
 * one rule: if a usable key cannot be produced, return null and let the
 * operators fall back to plain redaction. An unkeyed or weakly-keyed
 * surrogate would look like it was working while being trivially reversible.
 */
class PseudonymizerFactory
{
    /**
     * Create the pseudonymizer for the given profile, or return null when no usable key exists.
     */
    public static function forProfile(RedactorConfig $config): ?Pseudonymizer
    {
        $settings = $config->pseudonymization;

        if (($settings['enabled'] ?? true) === false) {
            return null;
        }

        // The salt is shared across profiles unless one sets its own, since two
        // logs must produce the same surrogate for the same user to be joined...
        $salt = $settings['salt'] ?? '';
        $salt = is_string($salt) ? $salt : '';

        try {
            $key = $settings['key'] ?? null;

            if (is_string($key) && $key !== '') {
                return Pseudonymizer::fromKey($key, $salt);
            }

            $applicationKey = config('app.key');

            if (! is_string($applicationKey) || $applicationKey === '') {
                InternalLog::warning('Pseudonymization is unavailable: no key configured and app.key is empty', [
                    'profile' => $config->profile,
                ]);

                return null;
            }

            return Pseudonymizer::derivedFrom($applicationKey, $salt);
        } catch (Throwable $e) {
            InternalLog::warning('Pseudonymization is unavailable; falling back to plain redaction', [
                'profile' => $config->profile,
                'reason' => $e->getMessage(),
            ]);

            return null;
        }
    }
}
