<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Support;

/**
 * Literal values that must never appear in output.
 *
 * Every other detector infers. This one knows: the application's own
 * credentials - the Stripe secret, the database password, the signing key -
 * are in config already, and a log line containing one of them verbatim is a
 * leak whatever it looks like. Matching is exact and case-sensitive, because
 * secrets are.
 *
 * Values shorter than the minimum are refused rather than registered: a
 * three-character "secret" would match inside ordinary words and redact half
 * the log.
 */
final class SecretRegistry
{
    public const MIN_LENGTH = 8;

    /** @var array<string, string> value => entity */
    private array $secrets = [];

    /**
     * @param  array<int, string>  $values
     */
    public function __construct(array $values = [], string $entity = 'known_secret')
    {
        foreach ($values as $value) {
            $this->add($value, $entity);
        }
    }

    /**
     * Register one value. Returns false if it was too short to be safe.
     */
    public function add(string $value, string $entity = 'known_secret'): bool
    {
        if (strlen($value) < self::MIN_LENGTH) {
            return false;
        }

        $this->secrets[$value] = $entity;

        return true;
    }

    public function isEmpty(): bool
    {
        return $this->secrets === [];
    }

    public function count(): int
    {
        return count($this->secrets);
    }

    /**
     * Every occurrence of every registered value in the subject.
     *
     * @return array<int, array{offset: int, value: string, entity: string}>
     */
    public function find(string $subject): array
    {
        $found = [];

        foreach ($this->secrets as $secret => $entity) {
            $offset = 0;

            while (($position = strpos($subject, $secret, $offset)) !== false) {
                $found[] = ['offset' => $position, 'value' => $secret, 'entity' => $entity];
                $offset = $position + strlen($secret);
            }
        }

        return $found;
    }

    /**
     * Merge another registry's values into a copy of this one.
     */
    public function merge(self $other): self
    {
        $merged = clone $this;

        foreach ($other->secrets as $value => $entity) {
            $merged->secrets[$value] = $entity;
        }

        return $merged;
    }
}
