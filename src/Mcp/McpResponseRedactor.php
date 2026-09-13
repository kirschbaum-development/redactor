<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Mcp;

use Generator;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Support\InternalLog;
use Laravel\Mcp\Transport\JsonRpcResponse;

/**
 * Redacts what an MCP server is about to hand to a model, and only that.
 *
 * A JSON-RPC result is mostly envelope: ids, protocol fields, cache hints,
 * server metadata, base64 blobs. The parts a model reads are the text
 * content of tool, resource and prompt responses, structured content, and
 * error messages. Those are redacted; the envelope and any binary content
 * are left exactly as they were, so the protocol stays valid and an image
 * is not mistaken for a high-entropy secret.
 */
final class McpResponseRedactor
{
    public function __construct(
        private readonly Redactor $redactor,
        private readonly ?string $profile = null,
    ) {}

    /**
     * @param  iterable<JsonRpcResponse>|JsonRpcResponse  $response
     * @return iterable<JsonRpcResponse>|JsonRpcResponse
     */
    public function redact(iterable|JsonRpcResponse $response): iterable|JsonRpcResponse
    {
        if ($response instanceof JsonRpcResponse) {
            return $this->redactOne($response);
        }

        return $this->redactEach($response);
    }

    /**
     * @param  iterable<JsonRpcResponse>  $responses
     * @return Generator<int, JsonRpcResponse>
     */
    private function redactEach(iterable $responses): Generator
    {
        foreach ($responses as $response) {
            yield $this->redactOne($response);
        }
    }

    private function redactOne(JsonRpcResponse $response): JsonRpcResponse
    {
        $content = $response->content;

        if (isset($content['result']) && is_array($content['result'])) {
            $content['result'] = $this->redactResult($content['result']);
        }

        if (isset($content['error']) && is_array($content['error']) && isset($content['error']['message']) && is_string($content['error']['message'])) {
            $content['error']['message'] = $this->text($content['error']['message']);
        }

        if (isset($content['params']) && is_array($content['params']) && isset($content['params']['content'])) {
            // A streamed notification carrying content, as a tool yields.
            $content['params'] = $this->redactResult($content['params']);
        }

        $response->content = $content;

        return $response;
    }

    /**
     * @param  array<array-key, mixed>  $result
     * @return array<array-key, mixed>
     */
    private function redactResult(array $result): array
    {
        // tools/call and streamed tool output
        if (isset($result['content']) && is_array($result['content'])) {
            $result['content'] = array_map(fn ($item) => $this->contentItem($item), $result['content']);
        }

        if (isset($result['structuredContent']) && is_array($result['structuredContent'])) {
            $result['structuredContent'] = $this->data($result['structuredContent']);
        }

        // resources/read
        if (isset($result['contents']) && is_array($result['contents'])) {
            $result['contents'] = array_map(fn ($item) => $this->contentItem($item), $result['contents']);
        }

        // prompts/get
        if (isset($result['messages']) && is_array($result['messages'])) {
            $result['messages'] = array_map(function ($message) {
                if (is_array($message) && isset($message['content'])) {
                    $message['content'] = is_array($message['content']) && ! array_is_list($message['content'])
                        ? $this->contentItem($message['content'])
                        : (is_string($message['content']) ? $this->text($message['content']) : $message['content']);
                }

                return $message;
            }, $result['messages']);
        }

        return $result;
    }

    /**
     * A content block: text is redacted, an embedded resource's text is
     * redacted, anything binary passes through.
     */
    private function contentItem(mixed $item): mixed
    {
        if (! is_array($item)) {
            return $item;
        }

        if (isset($item['text']) && is_string($item['text'])) {
            $item['text'] = $this->text($item['text']);
        }

        if (isset($item['resource']) && is_array($item['resource']) && isset($item['resource']['text']) && is_string($item['resource']['text'])) {
            $item['resource']['text'] = $this->text($item['resource']['text']);
        }

        return $item;
    }

    private function text(string $text): string
    {
        $out = $this->redactor->redactSafely($text, $this->profile);

        return is_string($out) ? $out : (string) json_encode($out);
    }

    /**
     * @param  array<array-key, mixed>  $data
     * @return array<array-key, mixed>
     */
    private function data(array $data): array
    {
        try {
            // No `_redacted` markers: structured content has a schema the
            // model was told about, and a key it does not expect breaks it.
            $out = $this->redactor->redactWithMetadata($data, $this->profile, mark: false)->value;
        } catch (\Throwable $e) {
            InternalLog::warning('MCP structured content could not be redacted; replaced as a precaution', [
                'profile' => $this->profile,
                'exception_type' => get_class($e),
                'exception_message' => $e->getMessage(),
            ]);

            return ['redaction' => 'failed'];
        }

        return is_array($out) ? $out : ['redaction' => $out];
    }
}
