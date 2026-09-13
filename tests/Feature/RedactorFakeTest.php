<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Facades\Redactor;
use Kirschbaum\Redactor\Logging\RedactorProcessor;
use Kirschbaum\Redactor\Redactor as RedactorService;
use Kirschbaum\Redactor\Testing\RedactorFake;
use Monolog\DateTimeImmutable;
use Monolog\Level;
use Monolog\LogRecord;
use PHPUnit\Framework\AssertionFailedError;

describe('Redactor::fake()', function () {
    it('swaps the facade and the container binding and still redacts', function () {
        $fake = Redactor::fake();

        expect(app(RedactorService::class))->toBe($fake)
            ->and(Redactor::redact(['password' => 'hunter2', 'id' => 1]))->toBe(['password' => '[REDACTED]', 'id' => 1, '_redacted' => true]);

        $fake->assertCalled(1);
        $fake->assertRedacted('password');
        $fake->assertNotRedacted('id');
        $fake->assertFinding('blocked_key');
        $fake->assertSomethingRedacted();
    });

    it('proves a secret never left, across every call and profile', function () {
        $fake = Redactor::fake();

        Redactor::redact('token sk_live_4eC39HqLyjWDarjtT1zdp7dc here');
        Redactor::redact(['note' => 'mail bob@example.com'], 'strict');
        Redactor::redactSafely(['nested' => ['password' => 'hunter2']]);

        $fake->assertNeverEmitted('sk_live_4eC39HqLyjWDarjtT1zdp7dc', 'bob@example.com', 'hunter2');
        $fake->assertProfileUsed('strict');
        $fake->assertCalled(3);
    });

    it('fails loudly when a secret did get out', function () {
        $fake = Redactor::fake();

        Redactor::redact(['comment' => 'my pin is 1234']);

        expect(fn () => $fake->assertNeverEmitted('1234'))->toThrow(AssertionFailedError::class, 'should have been redacted');
    });

    it('fails when nothing was redacted but something should have been', function () {
        $fake = Redactor::fake();

        Redactor::redact(['plain' => 'text']);

        expect(fn () => $fake->assertRedacted('plain'))->toThrow(AssertionFailedError::class, 'No redaction recorded')
            ->and(fn () => $fake->assertSomethingRedacted())->toThrow(AssertionFailedError::class);

        $fake->assertNothingRedacted();
    });

    it('records what went through the Monolog processor', function () {
        $fake = Redactor::fake();
        $processor = new RedactorProcessor(app(RedactorService::class));

        $processor(new LogRecord(new DateTimeImmutable(true), 'app', Level::Info, 'user bob@example.com', ['password' => 'x']));

        $fake->assertNeverEmitted('bob@example.com');
        $fake->assertRedacted('password');
    });

    it('can forget and be asserted empty', function () {
        $fake = Redactor::fake();
        Redactor::redact('x');
        $fake->forget();

        $fake->assertNotCalled();
        expect($fake)->toBeInstanceOf(RedactorFake::class)
            ->and($fake->recorded())->toBe([]);
    });
});
