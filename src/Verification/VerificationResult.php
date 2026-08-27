<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Verification;

/**
 * The outcome of checking one credential, and nothing else.
 *
 * Deliberately carries no trace of the secret. This object travels into JSON
 * and SARIF output that gets uploaded, attached to tickets and pasted into
 * chat - anything of the original riding along would turn a report about a leak
 * into a second leak.
 */
final readonly class VerificationResult
{
    private function __construct(
        public VerificationStatus $status,
        public string $note,
        public ?string $verifier = null,
    ) {}

    public static function active(string $note = 'The provider accepted this credential.', ?string $verifier = null): self
    {
        return new self(VerificationStatus::Active, $note, $verifier);
    }

    public static function inactive(string $note = 'The provider rejected this credential.', ?string $verifier = null): self
    {
        return new self(VerificationStatus::Inactive, $note, $verifier);
    }

    public static function unknown(string $note = 'Not verified.', ?string $verifier = null): self
    {
        return new self(VerificationStatus::Unknown, $note, $verifier);
    }

    public function withVerifier(string $verifier): self
    {
        return new self($this->status, $this->note, $verifier);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return array_filter([
            'status' => $this->status->value,
            'note' => $this->note,
            'verifier' => $this->verifier,
        ], fn ($v) => $v !== null);
    }
}
