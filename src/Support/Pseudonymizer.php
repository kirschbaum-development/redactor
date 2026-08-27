<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Support;

use RuntimeException;

/**
 * Turns a sensitive value into a stable stand-in.
 *
 * The same input always produces the same output, so redacted logs stay
 * joinable: you can still group by user, count distinct callers, or follow one
 * account through a trace - none of which survives replacing every value with
 * the same "[REDACTED]".
 *
 * The mapping is one-way. It is an HMAC, not encryption: there is no route back
 * from a surrogate to the original, by design. Anyone holding the key can
 * confirm a guess, which is why the key must not travel with the logs.
 */
final class Pseudonymizer
{
    /**
     * Minimum key length. Short keys make the confirm-a-guess attack cheap.
     */
    private const MIN_KEY_BYTES = 16;

    private function __construct(
        private readonly string $key,
        private readonly string $salt,
    ) {}

    public static function fromKey(string $key, string $salt = ''): self
    {
        if (strlen($key) < self::MIN_KEY_BYTES) {
            throw new RuntimeException(sprintf(
                'Redactor pseudonymization key must be at least %d bytes; got %d. '
                .'Set redactor.pseudonymization.key, or leave it null to derive one from APP_KEY.',
                self::MIN_KEY_BYTES,
                strlen($key)
            ));
        }

        return new self($key, $salt);
    }

    /**
     * Derive a key from the application key.
     *
     * Deriving rather than reusing APP_KEY directly means a leaked surrogate
     * corpus cannot be used to attack anything else signed with that key.
     */
    public static function derivedFrom(string $applicationKey, string $salt = ''): self
    {
        if (str_starts_with($applicationKey, 'base64:')) {
            $decoded = base64_decode(substr($applicationKey, 7), true);
            $applicationKey = $decoded === false ? $applicationKey : $decoded;
        }

        return self::fromKey(
            hash_hmac('sha256', 'kirschbaum/redactor/pseudonymization/v1', $applicationKey, true),
            $salt
        );
    }

    public function random(string $entity, string $value): DeterministicRandom
    {
        return new DeterministicRandom($this->key, $this->seed($entity, $value));
    }

    /**
     * A short, stable, URL-safe identifier for a value.
     */
    public function token(string $entity, string $value, int $length = 10): string
    {
        return $this->random($entity, $value)->token($length);
    }

    /**
     * A full hex digest, for callers that want to correlate without any
     * pretence that the result looks like the original.
     */
    public function digest(string $entity, string $value): string
    {
        return hash_hmac('sha256', $this->seed($entity, $value), $this->key);
    }

    /**
     * Normalising before hashing is what makes the pseudonym useful:
     * "Bob@Example.COM " and "bob@example.com" are the same person, and a
     * mapping that disagrees is not joinable.
     */
    private function seed(string $entity, string $value): string
    {
        return $this->salt.'|'.$entity.'|'.mb_strtolower(trim($value));
    }
}
