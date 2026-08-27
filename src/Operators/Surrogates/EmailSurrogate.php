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
 * Keeping the domain preserves the analysis people actually run on logs - which
 * tenant, which provider, how many distinct users at one company - while losing
 * the individual. Replacing it uses .invalid, which RFC 2606 guarantees can
 * never resolve, so a surrogate that escapes into a mail queue bounces instead
 * of reaching a stranger.
 */
final class EmailSurrogate implements SurrogateGenerator
{
    public function supports(string $entity, string $value): bool
    {
        return $entity === 'email' || (str_contains($value, '@') && substr_count($value, '@') === 1);
    }

    /**
     * @param  array<string, mixed>  $options
     */
    public function generate(string $value, DeterministicRandom $random, array $options = []): string
    {
        $at = strrpos($value, '@');

        if ($at === false) {
            return 'u_'.$random->token(6).'@example.invalid';
        }

        // Normalised, not raw. The seed already lowercases and trims, so a
        // domain taken verbatim would make "Alice@Customer.COM" and
        // "alice@customer.com" produce different surrogates - which silently
        // double-counts one user, the exact failure pseudonymisation exists to
        // avoid. Domains are case-insensitive by spec, so this loses nothing.
        $domain = strtolower(trim(substr($value, $at + 1)));
        $preserveDomain = ($options['preserve_domain'] ?? true) === true;

        $local = 'u_'.$random->token(6);

        return $local.'@'.($preserveDomain && $domain !== '' ? $domain : 'example.invalid');
    }
}
