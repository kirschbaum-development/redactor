<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Verification\Verifiers;

use Illuminate\Support\Facades\Http;
use Kirschbaum\Redactor\Verification\VerificationResult;
use Kirschbaum\Redactor\Verification\Verifier;
use Throwable;

/**
 * Checks a Google API key against a Google API.

 * A key that is real but not enabled for the API answers 403, which still
 * proves the key exists; only an explicitly invalid key answers 400.
 */
class GoogleApiKeyVerifier implements Verifier
{
    public function name(): string
    {
        return 'google_api_key';
    }

    public function host(): string
    {
        return 'generativelanguage.googleapis.com';
    }

    public function supports(string $entity, string $rule): bool
    {
        return in_array($entity, ['google_api_key', 'google'], true)
            || str_contains($rule, 'google');
    }

    public function verify(string $secret): VerificationResult
    {
        try {
            $response = Http::timeout(5)
                ->get('https://generativelanguage.googleapis.com/v1/models', ['key' => $secret]);

            if ($response->status() === 400) {
                return VerificationResult::inactive('Google rejected the key (400, API key not valid).');
            }

            if ($response->successful() || $response->status() === 403) {
                return VerificationResult::active('Google recognised the key; it is live and should be revoked.');
            }

            return VerificationResult::unknown(sprintf('Google returned %d.', $response->status()));
        } catch (Throwable $e) {
            return VerificationResult::unknown('Could not reach Google: '.$e->getMessage());
        }
    }
}
