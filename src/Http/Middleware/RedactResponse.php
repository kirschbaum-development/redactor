<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Streaming\StreamRedactor;
use Kirschbaum\Redactor\Support\InternalLog;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\StreamedResponse;
use Throwable;

/**
 * Redacts a response before it leaves the application.
 *
 *     Route::get('/export', ExportController::class)->middleware('redact:observability');
 *
 * JSON responses are redacted as data so structure and types survive; text is
 * redacted as text; a stream is redacted as it streams, with a hold-back so
 * nothing split across two chunks gets through; files pass through. The
 * profile's `_redacted` markers are never written into a response.
 *
 * Fails closed: if the response cannot be redacted the client gets a 500 with
 * none of the original body. Run `redactor:validate` at deploy time.
 */
class RedactResponse
{
    public function __construct(
        protected Redactor $redactor,
    ) {}

    public function handle(Request $request, Closure $next, ?string $profile = null): mixed
    {
        $response = $next($request);

        if (! $response instanceof Response || $response instanceof BinaryFileResponse) {
            return $response;
        }

        if ($response instanceof StreamedResponse) {
            $callback = $response->getCallback();

            if ($callback instanceof Closure) {
                $response->setCallback((new StreamRedactor($this->redactor, $profile))->wrap($callback));
            }

            return $response;
        }

        try {
            return $this->redact($response, $profile);
        } catch (Throwable $e) {
            InternalLog::warning('Response could not be redacted; replaced with an error response', [
                'profile' => $profile,
                'exception_type' => $e::class,
                'exception_message' => $e->getMessage(),
            ]);

            return new JsonResponse(['message' => 'The response could not be redacted.'], 500);
        }
    }

    protected function redact(Response $response, ?string $profile): Response
    {
        if ($response instanceof JsonResponse) {
            $data = $response->getData(true);

            return $response->setData($this->redactor->inspect($data, $profile, mark: false)->value);
        }

        $content = $response->getContent();

        if ($content === false || $content === '' || ! $this->isText($response)) {
            return $response;
        }

        $contentType = (string) $response->headers->get('Content-Type', '');

        if (str_contains($contentType, 'json')) {
            $decoded = json_decode($content, true);

            if (json_last_error() === JSON_ERROR_NONE) {
                $redacted = $this->redactor->inspect($decoded, $profile, mark: false)->value;
                $encoded = json_encode($redacted, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

                if ($encoded !== false) {
                    $response->setContent($encoded);

                    return $response;
                }
            }
        }

        $redacted = $this->redactor->inspect($content, $profile, mark: false)->value;

        $response->setContent(is_string($redacted) ? $redacted : (string) json_encode($redacted));

        return $response;
    }

    protected function isText(Response $response): bool
    {
        $type = strtolower((string) $response->headers->get('Content-Type', 'text/html'));

        return $type === ''
            || str_starts_with($type, 'text/')
            || str_contains($type, 'json')
            || str_contains($type, 'xml')
            || str_contains($type, 'javascript')
            || str_contains($type, 'x-www-form-urlencoded');
    }
}
