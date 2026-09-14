<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Ai;

use Closure;
use Illuminate\Container\Container;
use Kirschbaum\Redactor\Redactor;
use Laravel\Ai\Prompts\AgentPrompt;
use Laravel\Ai\Responses\AgentResponse;

/**
 * Redacts a prompt before it reaches the provider, and resolves tokens in the
 * answer on the way back.
 *
 *     class SupportAgent extends Agent implements HasMiddleware
 *     {
 *         public function middleware(): array
 *         {
 *             return [RedactPrompt::using('ai')];
 *         }
 *     }
 *
 * With a profile whose operators tokenise, the model sees
 * `tok_email_k4m9rp2xzq`, reasons about it, and the application receives
 * the real address back in the response text. With a profile that redacts
 * outright, the model simply never sees the value.
 */
class RedactPrompt
{
    public function __construct(
        protected Redactor $redactor,
        protected ?string $profile = null,
        protected bool $detokenizeResponse = true,
    ) {}

    public static function using(?string $profile, bool $detokenizeResponse = true): self
    {
        return new self(Container::getInstance()->make(Redactor::class), $profile, $detokenizeResponse);
    }

    /**
     * @param  Closure(AgentPrompt): AgentResponse  $next
     */
    public function handle(AgentPrompt $prompt, Closure $next): AgentResponse
    {
        $redacted = $this->redactor->redactSafely($prompt->prompt, $this->profile);

        $revised = $prompt->revise(is_string($redacted) ? $redacted : (string) json_encode($redacted));

        $response = $next($revised);

        if (! $this->detokenizeResponse) {
            return $response;
        }

        return $response->then(function (AgentResponse $response): void {
            $resolved = $this->redactor->detokenize($response->text);

            if (is_string($resolved)) {
                $response->text = $resolved;
            }
        });
    }
}
