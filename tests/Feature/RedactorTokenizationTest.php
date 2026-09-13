<?php

declare(strict_types=1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Kirschbaum\Redactor\Facades\Redactor;
use Kirschbaum\Redactor\Redactor as RedactorService;
use Kirschbaum\Redactor\Strategies\BlockedKeysStrategy;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;
use Kirschbaum\Redactor\Tokenization\Detokenizer;
use Kirschbaum\Redactor\Tokenization\TokenStore;

describe('Reversible tokens', function (): void {
    beforeEach(function (): void {
        config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        config()->set('redactor.pseudonymization.key', testPseudonymizationKey());
        config()->set('redactor.profiles.ai', [
            'enabled' => true,
            'strategies' => [BlockedKeysStrategy::class, RegexPatternsStrategy::class],
            'safe_keys' => [],
            'blocked_keys' => ['ssn'],
            'patterns' => [
                'email' => ['pattern' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/', 'entity' => 'email'],
                'card' => ['pattern' => '/\b\d{16}\b/', 'validator' => 'luhn', 'entity' => 'credit_card'],
            ],
            'operators' => ['default' => 'tokenize'],
            'replacement' => '[REDACTED]',
            'mark_redacted' => false,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => ['enabled' => false],
        ]);
    });

    it('replaces a value with a stable, model-friendly token', function (): void {
        $a = Redactor::redact('write to alice@customer.com today', 'ai');
        $b = Redactor::redact('alice@customer.com again', 'ai');

        expect($a)->toMatch('/^write to tok_email_[a-z0-9]{12} today$/');

        preg_match('/tok_email_[a-z0-9]{12}/', $a, $ma);
        preg_match('/tok_email_[a-z0-9]{12}/', $b, $mb);

        expect($ma[0])->toBe($mb[0]);
    });

    it('round-trips through detokenize, in strings and nested arrays', function (): void {
        $prompt = Redactor::redact(['user' => ['ssn' => '123-45-6789'], 'text' => 'mail alice@customer.com card 4111111111111111'], 'ai');

        expect($prompt['user']['ssn'])->toStartWith('tok_ssn_')
            ->and($prompt['text'])->not->toContain('alice@customer.com');

        $answer = "Reply to {$prompt['text']} and file under {$prompt['user']['ssn']}.";

        expect(Redactor::detokenize($answer))
            ->toBe('Reply to mail alice@customer.com card 4111111111111111 and file under 123-45-6789.')
            ->and(Redactor::detokenize($prompt))
            ->toBe(['user' => ['ssn' => '123-45-6789'], 'text' => 'mail alice@customer.com card 4111111111111111']);
    });

    it('leaves a token it does not know exactly as it is', function (): void {
        expect(Redactor::detokenize('see tok_email_zzzzzzzzzzzz and tok_made_up_by_model_abcdefghijkl'))
            ->toBe('see tok_email_zzzzzzzzzzzz and tok_made_up_by_model_abcdefghijkl');
    });

    it('keeps the original encrypted in the cache and forgets it on demand', function (): void {
        Redactor::redact('alice@customer.com', 'ai');

        $keys = [];
        foreach (Cache::getStore()->all() ?? [] as $k => $v) {
            $keys[$k] = $v;
        }

        $store = resolve(TokenStore::class);
        $token = (new Detokenizer($store))->tokensIn(Redactor::redact('alice@customer.com', 'ai'))[0];

        expect($store->get($token))->toBe('alice@customer.com')
            ->and(Cache::get('redactor:token:'.$token))->not->toContain('alice@customer.com');

        $store->forget($token);

        expect($store->get($token))->toBeNull()
            ->and(Redactor::detokenize($token))->toBe($token);
    });

    it('falls back to plain redaction when no pseudonymization key is available', function (): void {
        config()->set('redactor.pseudonymization', ['enabled' => false]);

        expect(Redactor::redact('alice@customer.com', 'ai'))->toBe('[REDACTED]');
    });

    it('honours a per-entity ttl option', function (): void {
        config()->set('redactor.profiles.ai.operators', ['default' => 'redact', 'email' => ['tokenize' => ['ttl' => 5]]]);

        $out = Redactor::redact('alice@customer.com', 'ai');
        $token = (new Detokenizer(resolve(TokenStore::class)))->tokensIn($out)[0];

        expect(resolve(TokenStore::class)->get($token))->toBe('alice@customer.com');

        $this->travel(6)->seconds();

        expect(resolve(TokenStore::class)->get($token))->toBeNull();
    });

    it('does not resolve the cache until something is tokenised', function (): void {
        $redactor = resolve(RedactorService::class);

        expect($redactor->operators()->has('tokenize'))->toBeTrue()
            ->and($redactor->redact('nothing sensitive'))->toBe('nothing sensitive');
    });
});
