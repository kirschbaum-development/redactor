<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Tokenization;

use Closure;

/**
 * Resolves the real store the first time a token is written or read.
 *
 * The redactor is built early, since other providers may resolve it during
 * their own register(), and the cache and encrypter it would need for tokens
 * may not be ready yet. Nothing touches them until a `tokenize` operator runs.
 */
class LazyTokenStore implements TokenStore
{
    private ?TokenStore $resolved = null;

    /**
     * Create a new lazy token store instance.
     *
     * @param  Closure(): TokenStore  $resolver
     */
    public function __construct(
        private readonly Closure $resolver,
    ) {}

    /**
     * Store the original value for a token.
     */
    public function put(string $token, string $value, string $entity, ?int $ttlSeconds = null): void
    {
        $this->store()->put($token, $value, $entity, $ttlSeconds);
    }

    /**
     * Get the original value for a token, if it is known.
     */
    public function get(string $token): ?string
    {
        return $this->store()->get($token);
    }

    /**
     * Forget a token.
     */
    public function forget(string $token): void
    {
        $this->store()->forget($token);
    }

    /**
     * Resolve the underlying store.
     */
    private function store(): TokenStore
    {
        return $this->resolved ??= ($this->resolver)();
    }
}
