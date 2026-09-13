<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Support;

use Kirschbaum\Redactor\Exceptions\PseudonymizationKeyException;

/**
 * Turns a sensitive value into a stable stand-in.
 *
 * The same input always produces the same output, so redacted logs stay
 * joinable: you can still group by user, count distinct callers, or follow one
 * account through a trace. The mapping is one-way: it is an HMAC, not
 * encryption, so there is no route back from a surrogate to the original.
 * Anyone holding the key can confirm a guess, which is why the key must not
 * travel with the logs.
 */
class Pseudonymizer
{
    /**
     * The minimum key length, since short keys make the confirm-a-guess attack cheap.
     */
    private const MIN_KEY_BYTES = 16;

    /**
     * Create a new pseudonymizer instance.
     */
    private function __construct(
        private readonly string $key,
        private readonly string $salt,
    ) {}

    /**
     * Create a pseudonymizer from an explicit key.
     *
     * @throws PseudonymizationKeyException
     */
    public static function fromKey(string $key, string $salt = ''): self
    {
        if (strlen($key) < self::MIN_KEY_BYTES) {
            throw new PseudonymizationKeyException(sprintf(
                'Redactor pseudonymization key must be at least %d bytes; got %d. '
                .'Set redactor.pseudonymization.key, or leave it null to derive one from APP_KEY.',
                self::MIN_KEY_BYTES,
                strlen($key)
            ));
        }

        return new self($key, $salt);
    }

    /**
     * Derive a pseudonymizer key from the application key.
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

    /**
     * Create a deterministic random stream for the given value.
     */
    public function random(string $entity, string $value): DeterministicRandom
    {
        return new DeterministicRandom($this->key, $this->seed($entity, $value));
    }

    /**
     * Get a short, stable, URL-safe identifier for a value.
     */
    public function token(string $entity, string $value, int $length = 10): string
    {
        return $this->random($entity, $value)->token($length);
    }

    /**
     * Get a full hex digest for a value, for correlating without any pretence of the original's shape.
     */
    public function digest(string $entity, string $value): string
    {
        return hash_hmac('sha256', $this->seed($entity, $value), $this->key);
    }

    /**
     * Get the normalised seed for a value.
     *
     * "Bob@Example.COM " and "bob@example.com" are the same person, and a
     * mapping that disagrees is not joinable.
     */
    private function seed(string $entity, string $value): string
    {
        return $this->salt.'|'.$entity.'|'.mb_strtolower(trim($value));
    }
}
