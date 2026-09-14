<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Verification\Verifiers;

use Illuminate\Support\Facades\Http;
use Kirschbaum\Redactor\Verification\VerificationResult;
use Kirschbaum\Redactor\Verification\Verifier;
use Throwable;

/**
 * Checks a SendGrid key by asking for its own scopes, which sends nothing.
 */
class SendGridKeyVerifier implements Verifier
{
    public function name(): string
    {
        return 'sendgrid_key';
    }

    public function host(): string
    {
        return 'api.sendgrid.com';
    }

    public function supports(string $entity, string $rule): bool
    {
        return in_array($entity, ['sendgrid_key', 'sendgrid'], true)
            || str_contains($rule, 'sendgrid');
    }

    public function verify(string $secret): VerificationResult
    {
        try {
            $response = Http::withToken($secret)
                ->timeout(5)
                ->get('https://api.sendgrid.com/v3/scopes');

            if (in_array($response->status(), [401, 403], true)) {
                return VerificationResult::inactive(sprintf('SendGrid rejected the key (%d).', $response->status()));
            }

            if ($response->successful()) {
                return VerificationResult::active('SendGrid accepted the key; it is live and should be revoked.');
            }

            return VerificationResult::unknown(sprintf('SendGrid returned %d.', $response->status()));
        } catch (Throwable $e) {
            return VerificationResult::unknown('Could not reach SendGrid: '.$e->getMessage());
        }
    }
}
