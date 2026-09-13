<?php

declare(strict_types=1);

namespace Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Kirschbaum\Redactor\Http\Middleware\RedactResponse;
use Kirschbaum\Redactor\Redactor;
use Symfony\Component\HttpFoundation\StreamedResponse;

describe('The redact middleware', function () {
    it('redacts a JSON response as data without writing markers into it', function () {
        Route::get('/me', fn () => response()->json(['id' => 7, 'email' => 'bob@example.com', 'password' => 'hunter2']))
            ->middleware('redact');

        $this->getJson('/me')
            ->assertOk()
            ->assertExactJson(['id' => 7, 'email' => '[REDACTED]', 'password' => '[REDACTED]']);
    });

    it('takes a profile', function () {
        config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));

        Route::get('/me', fn () => response()->json(['contact' => 'alice@customer.com']))
            ->middleware('redact:observability');

        $body = $this->getJson('/me')->assertOk()->json();

        expect($body['contact'])->toMatch('/^u_[a-z0-9]+@customer\.com$/');
    });

    it('redacts a plain text response as text', function () {
        Route::get('/note', fn () => response('contact bob@example.com', 200, ['Content-Type' => 'text/plain']))
            ->middleware('redact');

        $this->get('/note')->assertOk()->assertSee('contact [REDACTED]', false);
    });

    it('redacts a JSON string body that is not a JsonResponse as data', function () {
        Route::get('/raw', fn () => response('{"password":"hunter2","n":1}', 200, ['Content-Type' => 'application/json']))
            ->middleware('redact');

        $this->get('/raw')->assertOk()->assertExactJson(['password' => '[REDACTED]', 'n' => 1]);
    });

    it('leaves streamed and binary responses alone', function () {
        $middleware = new RedactResponse(app(Redactor::class));
        $stream = new StreamedResponse(fn () => print ('bob@example.com'));

        expect($middleware->handle(Request::create('/'), fn () => $stream))->toBe($stream);

        $image = response('bob@example.com', 200, ['Content-Type' => 'image/png']);

        expect($middleware->handle(Request::create('/'), fn () => $image)->getContent())->toBe('bob@example.com');
    });

    it('fails closed when the profile does not exist', function () {
        Route::get('/me', fn () => response()->json(['password' => 'hunter2']))
            ->middleware('redact:no_such_profile');

        $response = $this->getJson('/me');

        $response->assertStatus(500);
        expect($response->getContent())->not->toContain('hunter2');
    });

    it('keeps a typed field typed with the nullify operator', function () {
        config()->set('redactor.profiles.api', array_merge(config('redactor.profiles.default'), [
            'blocked_keys' => ['ssn', 'age'],
            'operators' => ['default' => 'redact', 'ssn' => 'nullify', 'age' => 'nullify'],
        ]));

        Route::get('/me', fn () => response()->json(['name' => 'n', 'ssn' => '123-45-6789', 'age' => 42]))
            ->middleware('redact:api');

        $this->getJson('/me')->assertOk()->assertExactJson(['name' => 'n', 'ssn' => null, 'age' => null]);
    });
});

describe('The nullify operator', function () {
    it('nulls a value found by its key, whatever its type, and reports it', function () {
        config()->set('redactor.profiles.api', array_merge(config('redactor.profiles.default'), [
            'blocked_keys' => ['secret'],
            'operators' => ['default' => 'nullify'],
            'mark_redacted' => false,
        ]));

        $result = app(Redactor::class)->redactWithMetadata([
            'secret' => ['nested' => 'x'],
            'other' => ['secret' => 12],
        ], 'api');

        expect($result->value)->toBe(['secret' => null, 'other' => ['secret' => null]])
            ->and($result->redactedKeys)->toBe(['secret']);
    });

    it('nulls a value at a path', function () {
        config()->set('redactor.profiles.api', array_merge(config('redactor.profiles.default'), [
            'paths' => ['meta.score' => 'nullify'],
            'mark_redacted' => false,
        ]));

        expect(app(Redactor::class)->redact(['meta' => ['score' => 9.5, 'ok' => true]], 'api'))
            ->toBe(['meta' => ['score' => null, 'ok' => true]]);
    });

    it('deletes a span inside a string, since a string has no null to write', function () {
        config()->set('redactor.profiles.api', array_merge(config('redactor.profiles.default'), [
            'operators' => ['default' => 'redact', 'email' => 'nullify'],
            'mark_redacted' => false,
        ]));

        expect(app(Redactor::class)->redact('mail bob@example.com now', 'api'))->toBe('mail  now');
    });
});
