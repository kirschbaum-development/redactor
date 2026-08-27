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
     * A stable name, used in config allowlists and in output.
     */
    public function name(): string;

    /**
     * The host this verifier sends the credential to.
     */
    public function host(): string;

    /**
     * Whether this verifier can check the given entity or rule.
     */
    public function supports(string $entity, string $rule): bool;

    /**
     * Check one credential. Must never throw and never log the secret.
     */
    public function verify(string $secret): VerificationResult;
}
