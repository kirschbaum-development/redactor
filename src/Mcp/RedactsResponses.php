<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Mcp;

use Illuminate\Container\Container;
use Kirschbaum\Redactor\Redactor;
use Laravel\Mcp\Server\ServerContext;
use Laravel\Mcp\Transport\JsonRpcRequest;
use Laravel\Mcp\Transport\JsonRpcResponse;

/**
 * Redacts everything a Laravel MCP server returns, over any transport.
 *
 *     class SupportServer extends Server
 *     {
 *         use RedactsResponses;
 *
 *         protected function redactionProfile(): ?string
 *         {
 *             return 'observability';
 *         }
 *     }
 *
 * Applied where the server produces its JSON-RPC responses, so it covers
 * tool results, resource reads, prompt messages, streamed tool output and
 * errors alike, whether the server speaks HTTP or stdio - and it is what the
 * server's own test helpers exercise, so a test of a tool tests the
 * redaction too.
 */
// @phpstan-ignore trait.unused
trait RedactsResponses
{
    /**
     * The profile to redact with; null for the default.
     */
    protected function redactionProfile(): ?string
    {
        return null;
    }

    /**
     * @return iterable<JsonRpcResponse>|JsonRpcResponse
     */
    protected function runMethodHandle(JsonRpcRequest $request, ServerContext $context): iterable|JsonRpcResponse
    {
        $response = parent::runMethodHandle($request, $context);

        return (new McpResponseRedactor(Container::getInstance()->make(Redactor::class), $this->redactionProfile()))->redact($response);
    }
}
