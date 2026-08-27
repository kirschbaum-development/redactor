<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor;

use Illuminate\Support\Facades\Config;
use Kirschbaum\Redactor\Support\InternalLog;
use Kirschbaum\Redactor\Support\Pseudonymizer;
use Throwable;

/**
 * Builds the pseudonymizer for a profile, or explains why it could not.
 *
 * Key handling is the whole security surface of pseudonymisation, so it is kept
 * in one place with one rule: if a usable key cannot be produced, return null
 * and let the operators fall back to plain redaction. Emitting an unkeyed or
 * weakly-keyed surrogate would look like it was working while being trivially
 * reversible - the worst of the available outcomes.
 */
final class PseudonymizerFactory
{
    public static function forProfile(RedactorConfig $config): ?Pseudonymizer
    {
        $settings = $config->pseudonymization;

        if (($settings['enabled'] ?? true) === false) {
            return null;
        }

        $salt = $settings['salt'] ?? $config->profile;
        $salt = is_string($salt) ? $salt : $config->profile;

        try {
            $key = $settings['key'] ?? null;

            if (is_string($key) && $key !== '') {
                return Pseudonymizer::fromKey($key, $salt);
            }

            $applicationKey = Config::get('app.key');

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
