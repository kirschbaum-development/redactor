<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Mcp\RedactsResponses;
use Laravel\Mcp\Request;
use Laravel\Mcp\Response;
use Laravel\Mcp\ResponseFactory;
use Laravel\Mcp\Server;
use Laravel\Mcp\Server\Prompt;
use Laravel\Mcp\Server\Resource;
use Laravel\Mcp\Server\Tool;

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

describe('RedactsResponses on an MCP server', function () {
    it('redacts a tool\'s text content', function () {
        RedactedServer::tool(LeakyTool::class)
            ->assertOk()
            ->assertDontSee('bob@example.com')
            ->assertDontSee('sk_live_4eC39HqLyjWDarjtT1zdp7dc')
            ->assertSee('[REDACTED]')
            ->assertSee('************1111');
    });

    it('redacts structured content as data, keeping its shape', function () {
        RedactedServer::tool(StructuredTool::class)
            ->assertOk()
            ->assertStructuredContent(['id' => 7, 'email' => '[REDACTED]', 'password' => '[REDACTED]']);
    });

    it('redacts JSON returned as text', function () {
        RedactedServer::tool(JsonTextTool::class)
            ->assertOk()
            ->assertDontSee('bob@example.com')
            ->assertSee('"id":7');
    });

    it('leaves binary content alone', function () {
        $response = RedactedServer::tool(BlobTool::class)->assertOk();

        $response->assertDontSee('[REDACTED]');
    });

    it('redacts an error message', function () {
        RedactedServer::tool(ErrorTool::class)
            ->assertHasErrors()
            ->assertDontSee('s3cr3t')
            ->assertSee('postgres://app:[REDACTED]@db.internal/app');
    });

    it('redacts a resource read', function () {
        RedactedServer::resource(CustomerResource::class)
            ->assertOk()
            ->assertDontSee('bob@example.com')
            ->assertSee('email: [REDACTED]');
    });

    it('redacts a prompt\'s messages', function () {
        RedactedServer::prompt(SummaryPrompt::class)
            ->assertOk()
            ->assertDontSee('bob@example.com')
            ->assertSee('************1111');
    });

    it('honours the profile the server names', function () {
        config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));

        ObservabilityServer::tool(LeakyTool::class)
            ->assertOk()
            ->assertDontSee('bob@example.com')
            ->assertSee('@example.com');
    });
});
