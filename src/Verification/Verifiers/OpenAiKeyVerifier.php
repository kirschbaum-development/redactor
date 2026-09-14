<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Verification\Verifiers;

use Illuminate\Support\Facades\Http;
use Kirschbaum\Redactor\Verification\VerificationResult;
use Kirschbaum\Redactor\Verification\Verifier;
use Throwable;

/**
 * Checks an OpenAI key against the models list, the cheapest authenticated call.
 */
class OpenAiKeyVerifier implements Verifier
{
    public function name(): string
    {
        return 'openai_key';
    }

    public function host(): string
    {
        return 'api.openai.com';
    }

    public function supports(string $entity, string $rule): bool
    {
        return in_array($entity, ['openai_key', 'openai'], true)
            || str_contains($rule, 'openai');
    }

    public function verify(string $secret): VerificationResult
    {
        try {
            $response = Http::withToken($secret)
                ->timeout(5)
                ->get('https://api.openai.com/v1/models');

            if ($response->status() === 401) {
                return VerificationResult::inactive('OpenAI rejected the key (401).');
            }

            if ($response->successful()) {
                return VerificationResult::active('OpenAI accepted the key; it is live and should be revoked.');
            }

            return VerificationResult::unknown(sprintf('OpenAI returned %d.', $response->status()));
        } catch (Throwable $e) {
            return VerificationResult::unknown('Could not reach OpenAI: '.$e->getMessage());
        }
    }
}
