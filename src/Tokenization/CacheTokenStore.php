<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Tokenization;

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Throwable;

/**
 * Tokens in the application cache, values encrypted at rest.
 *
 * The cache is the right home for a mapping that should not outlive the
 * conversation it served: a TTL bounds how long a token can be exchanged
 * back, and the encrypter means a dumped cache still says nothing. Anyone
 * holding both the cache and APP_KEY can resolve tokens, which is the same
 * trust the application itself needs; guard those, and the tokens are safe
 * to hand to a model.
 */
final class CacheTokenStore implements TokenStore
{
    public function __construct(
        private readonly Repository $cache,
        private readonly StringEncrypter $encrypter,
        private readonly ?int $defaultTtlSeconds = 86_400,
        private readonly string $prefix = 'redactor:token:',
    ) {}

    public function put(string $token, string $value, string $entity, ?int $ttlSeconds = null): void
    {
        $payload = $this->encrypter->encryptString($entity."\0".$value);
        $ttl = $ttlSeconds ?? $this->defaultTtlSeconds;

        if ($ttl === null) {
            $this->cache->forever($this->prefix.$token, $payload);
        } else {
            $this->cache->put($this->prefix.$token, $payload, $ttl);
        }
    }

    public function get(string $token): ?string
    {
        $payload = $this->cache->get($this->prefix.$token);

        if (! is_string($payload)) {
            return null;
        }

        try {
            $decrypted = $this->encrypter->decryptString($payload);
        } catch (Throwable) {
            // A key rotation or a corrupt entry: the token is simply unknown.
            return null;
        }

        $separator = strpos($decrypted, "\0");

        return $separator === false ? $decrypted : substr($decrypted, $separator + 1);
    }

    public function forget(string $token): void
    {
        $this->cache->forget($this->prefix.$token);
    }
}
