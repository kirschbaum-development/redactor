<?php

declare(strict_types=1);

namespace Tests\Feature;

use Generator;
use Kirschbaum\Redactor\Mcp\McpResponseRedactor;
use Kirschbaum\Redactor\Mcp\RedactsResponses;
use Kirschbaum\Redactor\Redactor;
use Laravel\Mcp\Request;
use Laravel\Mcp\Response;
use Laravel\Mcp\ResponseFactory;
use Laravel\Mcp\Server;
use Laravel\Mcp\Server\Prompt;
use Laravel\Mcp\Server\Resource;
use Laravel\Mcp\Server\Tool;
use Laravel\Mcp\Transport\JsonRpcResponse;

class LeakyTool extends Tool
{
    protected string $description = 'Returns a customer record';

    public function handle(Request $request): Response
    {
        return Response::text('Customer bob@example.com, card 4111111111111111, token sk_live_4eC39HqLyjWDarjtT1zdp7dc');
    }
}

class StructuredTool extends Tool
{
    protected string $description = 'Returns structured data';

    public function handle(Request $request): ResponseFactory
    {
        return Response::structured(['id' => 7, 'email' => 'bob@example.com', 'password' => 'hunter2']);
    }
}

class JsonTextTool extends Tool
{
    protected string $description = 'Returns JSON as text';

    public function handle(Request $request): Response
    {
        return Response::json(['id' => 7, 'email' => 'bob@example.com']);
    }
}

class BlobTool extends Tool
{
    protected string $description = 'Returns an image';

    public function handle(Request $request): Response
    {
        return Response::image(base64_encode(random_bytes(400)), 'image/png');
    }
}

class ErrorTool extends Tool
{
    protected string $description = 'Fails';

    public function handle(Request $request): Response
    {
        return Response::error('Could not reach postgres://app:s3cr3t@db.internal/app');
    }
}

class CustomerResource extends Resource
{
    protected string $description = 'A customer file';

    public function handle(Request $request): Response
    {
        return Response::text("name: Bob\nemail: bob@example.com\n");
    }
}

class SummaryPrompt extends Prompt
{
    protected string $description = 'Summarise a ticket';

    public function handle(Request $request): Response
    {
        return Response::text('Summarise the ticket from bob@example.com about card 4111111111111111');
    }
}

class RedactedServer extends Server
{
    use RedactsResponses;

    protected array $tools = [LeakyTool::class, StructuredTool::class, JsonTextTool::class, BlobTool::class, ErrorTool::class];

    protected array $resources = [CustomerResource::class];

    protected array $prompts = [SummaryPrompt::class];
}

class ObservabilityServer extends RedactedServer
{
    protected function redactionProfile(): ?string
    {
        return 'observability';
    }
}

describe('RedactsResponses on an MCP server', function (): void {
    it('redacts a tool\'s text content', function (): void {
        RedactedServer::tool(LeakyTool::class)
            ->assertOk()
            ->assertDontSee('bob@example.com')
            ->assertDontSee('sk_live_4eC39HqLyjWDarjtT1zdp7dc')
            ->assertSee('[REDACTED]')
            ->assertSee('************1111');
    });

    it('redacts structured content as data, keeping its shape', function (): void {
        RedactedServer::tool(StructuredTool::class)
            ->assertOk()
            ->assertStructuredContent(['id' => 7, 'email' => '[REDACTED]', 'password' => '[REDACTED]']);
    });

    it('redacts JSON returned as text', function (): void {
        RedactedServer::tool(JsonTextTool::class)
            ->assertOk()
            ->assertDontSee('bob@example.com')
            ->assertSee('"id":7');
    });

    it('leaves binary content alone', function (): void {
        $response = RedactedServer::tool(BlobTool::class)->assertOk();

        $response->assertDontSee('[REDACTED]');
    });

    it('redacts an error message', function (): void {
        RedactedServer::tool(ErrorTool::class)
            ->assertHasErrors()
            ->assertDontSee('s3cr3t')
            ->assertSee('postgres://app:[REDACTED]@db.internal/app');
    });

    it('redacts a resource read', function (): void {
        RedactedServer::resource(CustomerResource::class)
            ->assertOk()
            ->assertDontSee('bob@example.com')
            ->assertSee('email: [REDACTED]');
    });

    it('redacts a prompt\'s messages', function (): void {
        RedactedServer::prompt(SummaryPrompt::class)
            ->assertOk()
            ->assertDontSee('bob@example.com')
            ->assertSee('************1111');
    });

    it('honours the profile the server names', function (): void {
        config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));

        ObservabilityServer::tool(LeakyTool::class)
            ->assertOk()
            ->assertDontSee('bob@example.com')
            ->assertSee('@example.com');
    });
});

function mcpRedactor(?string $profile = null): McpResponseRedactor
{
    return new McpResponseRedactor(resolve(Redactor::class), $profile);
}

describe('McpResponseRedactor on raw JSON-RPC responses', function (): void {
    it('redacts each response of a streamed iterable as it is yielded', function (): void {
        $responses = (function (): Generator {
            yield JsonRpcResponse::result(1, ['content' => [['type' => 'text', 'text' => 'first bob@example.com']]]);
            yield JsonRpcResponse::result(2, ['content' => [['type' => 'text', 'text' => 'second sk_live_4eC39HqLyjWDarjtT1zdp7dc']]]);
        })();

        $out = mcpRedactor()->redact($responses);

        expect($out)->toBeInstanceOf(Generator::class);

        $texts = array_map(
            fn (JsonRpcResponse $r): string => $r->content['result']['content'][0]['text'],
            iterator_to_array($out, false)
        );

        expect($texts[0])->toBe('first [REDACTED]')
            ->and($texts[1])->not->toContain('sk_live_4eC39HqLyjWDarjtT1zdp7dc')
            ->and($texts[1])->toStartWith('second ');
    });

    it('redacts a JSON-RPC error message', function (): void {
        $response = mcpRedactor()->redact(JsonRpcResponse::error(1, -32000, 'failed for bob@example.com'));

        expect($response->content['error']['message'])->toBe('failed for [REDACTED]');
    });

    it('redacts the content a streamed notification carries', function (): void {
        $response = mcpRedactor()->redact(JsonRpcResponse::notification('notifications/message', [
            'content' => [['type' => 'text', 'text' => 'hi bob@example.com']],
        ]));

        expect($response->content['params']['content'][0]['text'])->toBe('hi [REDACTED]');
    });

    it('redacts a prompt message given as a bare string and leaves content that is not a block alone', function (): void {
        $response = mcpRedactor()->redact(JsonRpcResponse::result(1, [
            'messages' => [
                ['role' => 'user', 'content' => 'ask bob@example.com'],
                ['role' => 'assistant', 'content' => 42],
            ],
            'content' => ['not a block', ['type' => 'text', 'text' => 'from bob@example.com']],
        ]));

        $result = $response->content['result'];

        expect($result['messages'][0]['content'])->toBe('ask [REDACTED]')
            ->and($result['messages'][1]['content'])->toBe(42)
            ->and($result['content'][0])->toBe('not a block')
            ->and($result['content'][1]['text'])->toBe('from [REDACTED]');
    });

    it('redacts the text of a resource embedded in tool content', function (): void {
        $response = mcpRedactor()->redact(JsonRpcResponse::result(1, [
            'content' => [['type' => 'resource', 'resource' => ['uri' => 'file:///owner.txt', 'text' => 'owner bob@example.com']]],
        ]));

        expect($response->content['result']['content'][0]['resource']['text'])->toBe('owner [REDACTED]');
    });

    it('replaces structured content wholesale when it cannot be redacted', function (): void {
        $response = mcpRedactor('no_such_profile')->redact(JsonRpcResponse::result(1, [
            'structuredContent' => ['email' => 'bob@example.com'],
        ]));

        expect($response->content['result']['structuredContent'])->toBe(['redaction' => 'failed']);
    });
});
