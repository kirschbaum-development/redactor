<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Verification;

/**
 * Asks a provider whether one of its credentials is still live.
 *
 * Implementations send the secret to a third party. That is the entire point
 * and also the entire risk, so a verifier must declare which host it will
 * contact: the scan command names them before it starts, and an operator who
 * cannot allow that traffic finds out before it happens rather than in an
 * egress log afterwards.
 */
interface Verifier
{
    /**
     * Get the verifier's stable name, used in config allowlists and output.
     */
    public function name(): string;

    /**
     * Get the host this verifier sends the credential to.
     */
    public function host(): string;

    /**
     * Determine if this verifier can check the given entity or rule.
     */
    public function supports(string $entity, string $rule): bool;

    /**
     * Verify one credential without ever throwing or logging the secret.
     */
    public function verify(string $secret): VerificationResult;
}
