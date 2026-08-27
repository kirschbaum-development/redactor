<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Verification\Verifiers;

use Illuminate\Support\Facades\Http;
use Kirschbaum\Redactor\Verification\VerificationResult;
use Kirschbaum\Redactor\Verification\Verifier;
use Throwable;

/**
 * Checks a Stripe secret key against the API.
 *
 * Balance is read-only and returns 401 for a revoked key, so the check confirms
 * the key works without touching anything.
 */
final class StripeKeyVerifier implements Verifier
{
    public function name(): string
    {
        return 'stripe_key';
    }

    public function host(): string
    {
        return 'api.stripe.com';
    }

    public function supports(string $entity, string $rule): bool
    {
        return in_array($entity, ['stripe_key', 'stripe'], true)
            || str_contains($rule, 'stripe');
    }

    public function verify(string $secret): VerificationResult
    {
        try {
            $response = Http::withToken($secret)
                ->timeout(5)
                ->get('https://api.stripe.com/v1/balance');

            if ($response->status() === 401) {
                return VerificationResult::inactive('Stripe rejected the key (401).');
            }

            if ($response->successful()) {
                return VerificationResult::active('Stripe accepted the key; it is live and should be rolled.');
            }

            return VerificationResult::unknown(sprintf('Stripe returned %d.', $response->status()));
        } catch (Throwable $e) {
            return VerificationResult::unknown('Could not reach Stripe: '.$e->getMessage());
        }
    }
}
