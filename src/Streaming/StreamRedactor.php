<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Streaming;

use Generator;
use Kirschbaum\Redactor\Redactor;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * Redacts a stream chunk by chunk without ever letting a secret through split
 * across two chunks.
 *
 * A model streams tokens; a server sends events; a file is piped through.
 * Redacting each chunk on its own would miss every secret that straddles a
 * boundary, and buffering the whole stream would defeat the point of
 * streaming. So a window of the most recent bytes is held back: what is
 * emitted is always far enough behind the end of the input that no detection
 * starting in the emitted part could have continued into what has not been
 * seen yet. The cut falls on a line or word boundary, and a PEM block that
 * has opened but not closed is held whole.
 *
 * The hold-back is the latency of the stream in bytes, not time. For token
 * streams the default is a fraction of a second at typical rates; raise it
 * for content whose secrets are longer than a screen line.
 */
class StreamRedactor
{
    public const DEFAULT_HOLDBACK = 1024;

    private string $buffer = '';

    public function __construct(
        private readonly Redactor $redactor,
        private readonly ?string $profile = null,
        /** Bytes kept unemitted at the end of the buffer until more arrives. */
        private readonly int $holdback = self::DEFAULT_HOLDBACK,
    ) {}

    /**
     * Feed a chunk; get back whatever is now safe to emit, often nothing.
     */
    public function push(string $chunk): string
    {
        $this->buffer .= $chunk;

        $cut = $this->cutPoint();

        if ($cut <= 0) {
            return '';
        }

        $head = substr($this->buffer, 0, $cut);
        $this->buffer = substr($this->buffer, $cut);

        return $this->redact($head);
    }

    /**
     * The stream has ended: redact and return everything still held.
     */
    public function flush(): string
    {
        $rest = $this->buffer;
        $this->buffer = '';

        return $rest === '' ? '' : $this->redact($rest);
    }

    /**
     * Redact an iterable of chunks, yielding output as it becomes safe.
     *
     * @param  iterable<int|string, string>  $chunks
     * @return Generator<int, string>
     */
    public function through(iterable $chunks): Generator
    {
        foreach ($chunks as $chunk) {
            $out = $this->push($chunk);

            if ($out !== '') {
                yield $out;
            }
        }

        $out = $this->flush();

        if ($out !== '') {
            yield $out;
        }
    }

    /**
     * Wrap a callback that echoes its output, so what it echoes is redacted
     * on its way out. The output buffer hands over chunks of the given size.
     *
     * @return callable(): void
     */
    public function wrap(callable $callback, int $chunkSize = 4096): callable
    {
        return function () use ($callback, $chunkSize): void {
            ob_start(function (string $chunk, int $phase): string {
                $out = $this->push($chunk);

                if (($phase & PHP_OUTPUT_HANDLER_FINAL) !== 0) {
                    $out .= $this->flush();
                }

                return $out;
            }, $chunkSize);

            try {
                $callback();
            } finally {
                ob_end_flush();
            }
        };
    }

    /**
     * A streamed response whose callback's output is redacted as it streams.
     *
     * @param  array<string, string|array<int, string>>  $headers
     */
    public function response(callable $callback, int $status = 200, array $headers = [], int $chunkSize = 4096): StreamedResponse
    {
        return new StreamedResponse($this->wrap($callback, $chunkSize), $status, $headers);
    }

    /**
     * Where the buffer can be cut so nothing emitted could be half a secret.
     *
     * Returns 0 when nothing can be emitted yet.
     */
    private function cutPoint(): int
    {
        $length = strlen($this->buffer);

        if ($length <= $this->holdback) {
            return 0;
        }

        $limit = $length - $this->holdback;

        // A PEM block is one secret however many lines it spans: hold it
        // while it is open, and once closed hold it until it can go whole.
        $begin = strrpos($this->buffer, '-----BEGIN');

        if ($begin !== false) {
            $end = strpos($this->buffer, '-----END', $begin);

            if ($end === false) {
                $limit = min($limit, $begin);
            } else {
                $endLine = strpos($this->buffer, "\n", $end);
                $blockEnd = $endLine === false ? $length : $endLine + 1;

                if ($limit < $blockEnd) {
                    $limit = min($limit, $begin);
                }
            }
        }

        return $limit <= 0 ? 0 : $this->boundaryBefore($limit);
    }

    /**
     * Where before $limit the buffer can be cut without splitting a secret.
     *
     * A line end is always safe: no shipped rule except the PEM block, which
     * is handled above, matches across a newline. A word boundary is not - a
     * spaced card number or a formatted phone number spans several - so it is
     * used only when a whole extra window has passed with no line end at all,
     * as in a token stream that has not produced a newline for a while. With
     * no boundary of either kind, nothing is emitted until the unbroken run
     * has outlived a window: at that point it cannot be a single token any
     * detector would recognise, and holding it forever would stall the stream.
     */
    private function boundaryBefore(int $limit): int
    {
        $head = substr($this->buffer, 0, $limit);
        $newline = strrpos($head, "\n");

        if ($newline !== false) {
            return $newline + 1;
        }

        if ($limit < $this->holdback) {
            return 0;
        }

        if (preg_match('/\s(?=\S*$)/', $head, $m, PREG_OFFSET_CAPTURE) === 1) {
            return (int) $m[0][1] + 1;
        }

        return $limit;
    }

    private function redact(string $text): string
    {
        $out = $this->redactor->redactSafely($text, $this->profile);

        return is_string($out) ? $out : (string) json_encode($out);
    }
}
