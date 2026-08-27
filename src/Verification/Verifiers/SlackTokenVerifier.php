<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Verification\Verifiers;

use Illuminate\Support\Facades\Http;
use Kirschbaum\Redactor\Verification\VerificationResult;
use Kirschbaum\Redactor\Verification\Verifier;
use Throwable;

/**
 * Checks a Slack token via auth.test.
 *
 * Slack answers 200 either way and reports failure in the body, so the status
 * code alone would call every dead token live.
 */
final class SlackTokenVerifier implements Verifier
{
    public function name(): string
    {
        return 'slack_token';
    }

    public function host(): string
    {
        return 'slack.com';
    }

    public function supports(string $entity, string $rule): bool
    {
        return in_array($entity, ['slack_token', 'slack'], true)
            || str_contains($rule, 'slack');
    }

    public function verify(string $secret): VerificationResult
    {
        try {
            $response = Http::withToken($secret)
                ->timeout(5)
                ->post('https://slack.com/api/auth.test');

            if (! $response->successful()) {
                return VerificationResult::unknown(sprintf('Slack returned %d.', $response->status()));
            }

            $ok = $response->json('ok');

            if ($ok === true) {
                return VerificationResult::active('Slack accepted the token; it is live and should be revoked.');
            }

            if ($ok === false) {
                $error = $response->json('error');

                return VerificationResult::inactive(sprintf(
                    'Slack rejected the token (%s).',
                    is_string($error) ? $error : 'not ok'
                ));
            }

            return VerificationResult::unknown('Slack returned an unexpected response.');
        } catch (Throwable $e) {
            return VerificationResult::unknown('Could not reach Slack: '.$e->getMessage());
        }
    }
}
