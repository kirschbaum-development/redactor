<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Ai\RedactPrompt;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;
use Laravel\Ai\Contracts\Agent;
use Laravel\Ai\Contracts\Providers\TextProvider;
use Laravel\Ai\Prompts\AgentPrompt;
use Laravel\Ai\Responses\AgentResponse;
use Laravel\Ai\Responses\Data\Meta;
use Laravel\Ai\Responses\Data\Usage;
use Mockery;

function agentPrompt(string $text): AgentPrompt
{
    return new AgentPrompt(
        Mockery::mock(Agent::class),
        $text,
        [],
        Mockery::mock(TextProvider::class),
        'test-model',
    );
}

function agentResponse(string $text): AgentResponse
{
    return new AgentResponse('inv-1', $text, new Usage, new Meta);
}

describe('RedactPrompt middleware', function () {
    beforeEach(function () {
        config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        config()->set('redactor.pseudonymization.key', testPseudonymizationKey());
        config()->set('redactor.profiles.ai', [
            'enabled' => true,
            'strategies' => [RegexPatternsStrategy::class],
            'safe_keys' => [],
            'blocked_keys' => [],
            'patterns' => ['email' => ['pattern' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/', 'entity' => 'email']],
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

    it('redacts the prompt the provider sees and resolves tokens in the answer', function () {
        $seen = null;

        $response = RedactPrompt::using('ai')->handle(agentPrompt('Reply to alice@customer.com politely'), function (AgentPrompt $prompt) use (&$seen): AgentResponse {
            $seen = $prompt->prompt;

            preg_match('/tok_email_[a-z0-9]{12}/', $prompt->prompt, $m);

            return agentResponse("Dear {$m[0]}, thank you.");
        });

        expect($seen)->toMatch('/^Reply to tok_email_[a-z0-9]{12} politely$/')
            ->and($seen)->not->toContain('alice@customer.com')
            ->and($response->text)->toBe('Dear alice@customer.com, thank you.');
    });

    it('redacts outright with a profile that does not tokenise, and touches nothing on the way back', function () {
        $middleware = new RedactPrompt(app(Redactor::class), 'default');

        $response = $middleware->handle(agentPrompt('Reply to alice@customer.com'), function (AgentPrompt $prompt): AgentResponse {
            expect($prompt->prompt)->toBe('Reply to [REDACTED]');

            return agentResponse('Done.');
        });

        expect($response->text)->toBe('Done.');
    });

    it('can leave tokens in the answer when asked', function () {
        $response = RedactPrompt::using('ai', detokenizeResponse: false)->handle(agentPrompt('alice@customer.com'), function (AgentPrompt $prompt): AgentResponse {
            return agentResponse('echo '.$prompt->prompt);
        });

        expect($response->text)->toMatch('/^echo tok_email_[a-z0-9]{12}$/');
    });
});
