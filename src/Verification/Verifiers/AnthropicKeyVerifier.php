<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Verification\Verifiers;

use Illuminate\Support\Facades\Http;
use Kirschbaum\Redactor\Verification\VerificationResult;
use Kirschbaum\Redactor\Verification\Verifier;
use Throwable;

/**
 * Checks an Anthropic key against the models list, the cheapest authenticated call.
 */
class AnthropicKeyVerifier implements Verifier
{
    public function name(): string
    {
        return 'anthropic_key';
    }

    public function host(): string
    {
        return 'api.anthropic.com';
    }

    public function supports(string $entity, string $rule): bool
    {
        return in_array($entity, ['anthropic_key', 'anthropic'], true)
            || str_contains($rule, 'anthropic');
    }

    public function verify(string $secret): VerificationResult
    {
        try {
            $response = Http::withHeaders([
                'x-api-key' => $secret,
                'anthropic-version' => '2023-06-01',
            ])->timeout(5)->get('https://api.anthropic.com/v1/models');

            if ($response->status() === 401) {
                return VerificationResult::inactive('Anthropic rejected the key (401).');
            }

            if ($response->successful()) {
                return VerificationResult::active('Anthropic accepted the key; it is live and should be revoked.');
            }

            return VerificationResult::unknown(sprintf('Anthropic returned %d.', $response->status()));
        } catch (Throwable $e) {
            return VerificationResult::unknown('Could not reach Anthropic: '.$e->getMessage());
        }
    }
}
