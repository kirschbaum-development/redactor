<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Verification\Verifiers;

use Illuminate\Support\Facades\Http;
use Kirschbaum\Redactor\Verification\VerificationResult;
use Kirschbaum\Redactor\Verification\Verifier;
use Throwable;

/**
 * Checks a GitHub token against the API's identity endpoint.
 *
 * /user is the cheapest call that distinguishes live from dead: it needs no
 * scopes beyond authentication and returns 401 for a revoked or expired token.
 */
final class GitHubTokenVerifier implements Verifier
{
    public function name(): string
    {
        return 'github_token';
    }

    public function host(): string
    {
        return 'api.github.com';
    }

    public function supports(string $entity, string $rule): bool
    {
        return in_array($entity, ['github_token', 'github'], true)
            || str_contains($rule, 'github');
    }

    public function verify(string $secret): VerificationResult
    {
        try {
            $response = Http::withHeaders([
                'Authorization' => 'Bearer '.$secret,
                'Accept' => 'application/vnd.github+json',
                'User-Agent' => 'kirschbaum-redactor',
            ])->timeout(5)->get('https://api.github.com/user');

            if ($response->status() === 401) {
                return VerificationResult::inactive('GitHub rejected the token (401).');
            }

            if ($response->successful()) {
                return VerificationResult::active('GitHub accepted the token; it is live and should be revoked.');
            }

            return VerificationResult::unknown(sprintf('GitHub returned %d.', $response->status()));
        } catch (Throwable $e) {
            // The message is safe to surface; the secret never appears in it.
            return VerificationResult::unknown('Could not reach GitHub: '.$e->getMessage());
        }
    }
}
