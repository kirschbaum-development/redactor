<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Tokenization;

/**
 * Where a token's original value lives while the token is out in the world.
 *
 * A surrogate is one-way by design. A token is a surrogate that can be
 * exchanged back - by the application, never by whoever received it - which
 * is what an AI boundary needs: the model sees `tok_email_k4m9rp2xzq`, refers
 * to it in its answer, and the application resolves it to the real address
 * before acting. The store is the only place that mapping exists.
 */
interface TokenStore
{
    public function put(string $token, string $value, string $entity, ?int $ttlSeconds = null): void;

    public function get(string $token): ?string;

    public function forget(string $token): void;
}
