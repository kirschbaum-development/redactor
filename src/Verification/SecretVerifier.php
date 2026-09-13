<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Verification;

use Kirschbaum\Redactor\Verification\Verifiers\GitHubTokenVerifier;
use Kirschbaum\Redactor\Verification\Verifiers\SlackTokenVerifier;
use Kirschbaum\Redactor\Verification\Verifiers\StripeKeyVerifier;
use Throwable;

/**
 * Decides whether a credential may be checked, and checks it.
 *
 * Checking a secret means sending it to a third party, so verification is off
 * unless three independent things all say yes: config enables it, the caller
 * passes --verify, and the verifier is on the allowlist. Any one missing means
 * nothing leaves the machine. There is deliberately no way to turn this on
 * from the redaction path, which runs unattended inside applications.
 */
class SecretVerifier
{
    /** @var array<int, Verifier> */
    private array $verifiers;

    /**
     * @param  array<int, string>  $allowed  verifier names permitted to run
     * @param  array<int, Verifier>|null  $verifiers  overridable for testing
     */
    public function __construct(
        private readonly array $allowed = [],
        ?array $verifiers = null,
    ) {
        $this->verifiers = $verifiers ?? [
            new GitHubTokenVerifier,
            new StripeKeyVerifier,
            new SlackTokenVerifier,
        ];
    }

    /**
     * Create a verifier from config, or null if config does not permit any.
     *
     * @param  array<string, mixed>  $settings
     * @param  array<int, Verifier>|null  $verifiers
     */
    public static function fromConfig(array $settings, ?array $verifiers = null): ?self
    {
        if (($settings['enabled'] ?? false) !== true) {
            return null;
        }

        $allowed = $settings['verifiers'] ?? [];
        $allowed = is_array($allowed) ? array_values(array_filter($allowed, 'is_string')) : [];

        // An empty allowlist means "none", not "all"; enabling is separate from choosing who to trust...
        return $allowed === [] ? null : new self($allowed, $verifiers);
    }

    /**
     * Get the verifiers that are permitted to run.
     *
     * @return array<int, Verifier>
     */
    public function enabled(): array
    {
        return array_values(array_filter(
            $this->verifiers,
            fn (Verifier $v) => in_array($v->name(), $this->allowed, true)
        ));
    }

    /**
     * Get every host a run could contact, so the operator can be told up front.
     *
     * @return array<int, string>
     */
    public function hosts(): array
    {
        $hosts = array_map(fn (Verifier $v) => $v->host(), $this->enabled());
        sort($hosts);

        return array_values(array_unique($hosts));
    }

    public function canVerify(string $entity, string $rule): bool
    {
        return $this->verifierFor($entity, $rule) !== null;
    }

    /**
     * Verify one secret, or report Unknown if nothing is allowed to.
     *
     * Never throws: a verification failure must degrade the finding to Unknown,
     * not abandon a scan that has already found real problems.
     */
    public function verify(string $entity, string $rule, string $secret): VerificationResult
    {
        $verifier = $this->verifierFor($entity, $rule);

        if ($verifier === null) {
            return VerificationResult::unknown('No verifier is enabled for this kind of credential.');
        }

        try {
            return $verifier->verify($secret)->withVerifier($verifier->name());
        } catch (Throwable $e) {
            return VerificationResult::unknown(
                'The verifier failed: '.$e->getMessage(),
                $verifier->name()
            );
        }
    }

    private function verifierFor(string $entity, string $rule): ?Verifier
    {
        foreach ($this->enabled() as $verifier) {
            if ($verifier->supports($entity, $rule)) {
                return $verifier;
            }
        }

        return null;
    }
}
