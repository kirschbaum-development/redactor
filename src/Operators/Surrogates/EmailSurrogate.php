<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Operators\Surrogates;

use Kirschbaum\Redactor\Support\DeterministicRandom;

/**
 * A stable fake address for a real one.
 *
 *     alice@customer.com  ->  u_7f3ac9@customer.com        (domain kept)
 *     alice@customer.com  ->  u_7f3ac9@example.invalid     (domain replaced)
 *
 * Keeping the domain preserves the analysis people run on logs, which tenant,
 * which provider, how many distinct users at one company, while losing the
 * individual. Replacing it uses .invalid, which RFC 2606 guarantees can never
 * resolve, so a surrogate that escapes into a mail queue bounces instead of
 * reaching a stranger.
 */
class EmailSurrogate implements SurrogateGenerator
{
    /**
     * Determine if the value is an email address or is flagged as one.
     */
    public function supports(string $entity, string $value): bool
    {
        return $entity === 'email' || (str_contains($value, '@') && substr_count($value, '@') === 1);
    }

    /**
     * Generate a surrogate address for the given one.
     *
     * @param  array<string, mixed>  $options
     */
    public function generate(string $value, DeterministicRandom $random, array $options = []): string
    {
        $at = strrpos($value, '@');

        if ($at === false) {
            return 'u_'.$random->token(6).'@example.invalid';
        }

        // Normalised rather than raw, since the seed already lowercases and trims and a
        // verbatim domain would give "Alice@Customer.COM" a different surrogate from
        // "alice@customer.com", silently double-counting one user...
        $domain = strtolower(trim(substr($value, $at + 1)));
        $preserveDomain = ($options['preserve_domain'] ?? true) === true;

        $local = 'u_'.$random->token(6);

        return $local.'@'.($preserveDomain && $domain !== '' ? $domain : 'example.invalid');
    }
}
