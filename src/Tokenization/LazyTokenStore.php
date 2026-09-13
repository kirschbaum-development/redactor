<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Tokenization;

use Closure;

/**
 * Resolves the real store the first time a token is written or read.
 *
 * The redactor is built early - other providers may resolve it during their
 * own register() - and the cache and encrypter it would need for tokens may
 * not be ready yet. Nothing touches them until a `tokenize` operator runs.
 */
final class LazyTokenStore implements TokenStore
{
    private ?TokenStore $resolved = null;

    /**
     * @param  Closure(): TokenStore  $resolver
     */
    public function __construct(
        private readonly Closure $resolver,
    ) {}

    public function put(string $token, string $value, string $entity, ?int $ttlSeconds = null): void
    {
        $this->store()->put($token, $value, $entity, $ttlSeconds);
    }

    public function get(string $token): ?string
    {
        return $this->store()->get($token);
    }

    public function forget(string $token): void
    {
        $this->store()->forget($token);
    }

    private function store(): TokenStore
    {
        return $this->resolved ??= ($this->resolver)();
    }
}
