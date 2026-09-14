<?php

declare(strict_types=1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Event;
use Kirschbaum\Redactor\Events\RedactionPerformed;
use Kirschbaum\Redactor\Redactor;

describe('RedactionPerformed', function (): void {
    it('is dispatched with names and counts, never values', function (): void {
        Event::fake([RedactionPerformed::class]);

        resolve(Redactor::class)->redact(['password' => 'hunter2', 'note' => 'mail bob@example.com and alice@example.com']);

        Event::assertDispatched(RedactionPerformed::class, function (RedactionPerformed $event): bool {
            $serialised = json_encode($event);

            return $event->profile === 'default'
                && $event->redactedKeys === ['password', 'note']
                && $event->rules === ['blocked_key' => 1, 'email' => 2]
                && $event->entities === ['password' => 1, 'email' => 2]
                && $event->findings === 3
                && ! str_contains((string) $serialised, 'hunter2')
                && ! str_contains((string) $serialised, 'bob@example.com');
        });
    });

    it('is not dispatched when nothing was redacted', function (): void {
        Event::fake([RedactionPerformed::class]);

        resolve(Redactor::class)->redact(['plain' => 'text']);

        Event::assertNotDispatched(RedactionPerformed::class);
    });

    it('can be switched off', function (): void {
        config()->set('redactor.events', false);
        Event::fake([RedactionPerformed::class]);

        (new Redactor)->redact(['password' => 'x']);

        Event::assertNotDispatched(RedactionPerformed::class);
    });

    it('never lets a failing listener break redaction', function (): void {
        Event::listen(RedactionPerformed::class, fn () => throw new \RuntimeException('metrics down'));

        expect(resolve(Redactor::class)->redact(['password' => 'x']))->toBe(['password' => '[REDACTED]', '_redacted' => true]);
    });
});
