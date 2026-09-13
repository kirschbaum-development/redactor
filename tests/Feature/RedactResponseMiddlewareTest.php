<?php

declare(strict_types=1);

namespace Tests\Feature;

use Illuminate\Contracts\Routing\ResponseFactory;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Kirschbaum\Redactor\Http\Middleware\RedactResponse;
use Kirschbaum\Redactor\Redactor;
use Symfony\Component\HttpFoundation\StreamedResponse;

describe('The redact middleware', function (): void {
    it('redacts a JSON response as data without writing markers into it', function (): void {
        Route::get('/me', fn () => response()->json(['id' => 7, 'email' => 'bob@example.com', 'password' => 'hunter2']))
            ->middleware('redact');

        $this->getJson('/me')
            ->assertOk()
            ->assertExactJson(['id' => 7, 'email' => '[REDACTED]', 'password' => '[REDACTED]']);
    });

    it('takes a profile', function (): void {
        config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));

        Route::get('/me', fn () => response()->json(['contact' => 'alice@customer.com']))
            ->middleware('redact:observability');

        $body = $this->getJson('/me')->assertOk()->json();

        expect($body['contact'])->toMatch('/^u_[a-z0-9]+@customer\.com$/');
    });

    it('redacts a plain text response as text', function (): void {
        Route::get('/note', fn (): ResponseFactory|\Illuminate\Http\Response => response('contact bob@example.com', 200, ['Content-Type' => 'text/plain']))
            ->middleware('redact');

        $this->get('/note')->assertOk()->assertSee('contact [REDACTED]', false);
    });

    it('redacts a JSON string body that is not a JsonResponse as data', function (): void {
        Route::get('/raw', fn (): ResponseFactory|\Illuminate\Http\Response => response('{"password":"hunter2","n":1}', 200, ['Content-Type' => 'application/json']))
            ->middleware('redact');

        $this->get('/raw')->assertOk()->assertExactJson(['password' => '[REDACTED]', 'n' => 1]);
    });

    it('leaves streamed and binary responses alone', function (): void {
        $middleware = new RedactResponse(resolve(Redactor::class));
        $stream = new StreamedResponse(fn (): int => print ('bob@example.com'));

        expect($middleware->handle(Request::create('/'), fn (): StreamedResponse => $stream))->toBe($stream);

        $image = response('bob@example.com', 200, ['Content-Type' => 'image/png']);

        expect($middleware->handle(Request::create('/'), fn (): ResponseFactory|\Illuminate\Http\Response => $image)->getContent())->toBe('bob@example.com');
    });

    it('fails closed when the profile does not exist', function (): void {
        Route::get('/me', fn () => response()->json(['password' => 'hunter2']))
            ->middleware('redact:no_such_profile');

        $response = $this->getJson('/me');

        $response->assertStatus(500);
        expect($response->getContent())->not->toContain('hunter2');
    });

    it('keeps a typed field typed with the nullify operator', function (): void {
        config()->set('redactor.profiles.api', array_merge(config('redactor.profiles.default'), [
            'blocked_keys' => ['ssn', 'age'],
            'operators' => ['default' => 'redact', 'ssn' => 'nullify', 'age' => 'nullify'],
        ]));

        Route::get('/me', fn () => response()->json(['name' => 'n', 'ssn' => '123-45-6789', 'age' => 42]))
            ->middleware('redact:api');

        $this->getJson('/me')->assertOk()->assertExactJson(['name' => 'n', 'ssn' => null, 'age' => null]);
    });
});

describe('The nullify operator', function (): void {
    it('nulls a value found by its key, whatever its type, and reports it', function (): void {
        config()->set('redactor.profiles.api', array_merge(config('redactor.profiles.default'), [
            'blocked_keys' => ['secret'],
            'operators' => ['default' => 'nullify'],
            'mark_redacted' => false,
        ]));

        $result = resolve(Redactor::class)->inspect([
            'secret' => ['nested' => 'x'],
            'other' => ['secret' => 12],
        ], 'api');

        expect($result->value)->toBe(['secret' => null, 'other' => ['secret' => null]])
            ->and($result->redactedKeys)->toBe(['secret']);
    });

    it('nulls a value at a path', function (): void {
        config()->set('redactor.profiles.api', array_merge(config('redactor.profiles.default'), [
            'paths' => ['meta.score' => 'nullify'],
            'mark_redacted' => false,
        ]));

        expect(resolve(Redactor::class)->redact(['meta' => ['score' => 9.5, 'ok' => true]], 'api'))
            ->toBe(['meta' => ['score' => null, 'ok' => true]]);
    });

    it('deletes a span inside a string, since a string has no null to write', function (): void {
        config()->set('redactor.profiles.api', array_merge(config('redactor.profiles.default'), [
            'operators' => ['default' => 'redact', 'email' => 'nullify'],
            'mark_redacted' => false,
        ]));

        expect(resolve(Redactor::class)->redact('mail bob@example.com now', 'api'))->toBe('mail  now');
    });
});
