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
 * Verification is the single most useful thing a secret scanner can do - it
 * turns a wall of maybes into a short list of live keys - and the single most
 * dangerous, because checking a secret means sending it to a third party. A
 * scan that quietly posted every candidate it found to half a dozen APIs would
 * be an exfiltration tool wearing a security tool's name.
 *
 * So it is off unless three independent things all say yes:
 *
 *   1. config enables it                (a deliberate, reviewable change)
 *   2. the caller passes --verify       (a per-run decision by a human)
 *   3. the verifier is on the allowlist (which providers, specifically)
 *
 * Any one of them missing means nothing leaves the machine. There is
 * deliberately no way to turn this on from the redaction path at all: redaction
 * runs unattended inside applications, and nothing unattended should be making
 * outbound calls with secrets in them.
 */
final class SecretVerifier
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
     * Build a verifier from config, or null if config does not permit any.
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

        // An empty allowlist means "none", not "all". Enabling the feature is a
        // separate decision from choosing who to trust with the secrets.
        return $allowed === [] ? null : new self($allowed, $verifiers);
    }

    /**
     * The verifiers that would actually run.
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
     * Every host a run could contact, so the operator can be told up front.
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
     * Check one secret, or report Unknown if nothing is allowed to.
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
