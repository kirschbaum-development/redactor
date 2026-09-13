<?php

declare(strict_types=1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Date;
use Kirschbaum\Redactor\Logging\RedactorProcessor;
use Kirschbaum\Redactor\Redactor;
use Monolog\DateTimeImmutable;
use Monolog\Formatter\LineFormatter;
use Monolog\Level;
use Monolog\LogRecord;

enum OpaqueStatus: string
{
    case Active = 'active';
}

function opaqueRecord(array $context): LogRecord
{
    return new LogRecord(new DateTimeImmutable(true), 'testing', Level::Error, 'boom', $context);
}

describe('Opaque objects', function (): void {
    it('passes a Throwable through untouched so the formatter still renders the trace', function (): void {
        $exception = new \RuntimeException('db down');

        $result = (new RedactorProcessor(resolve(Redactor::class)))(opaqueRecord(['exception' => $exception]));

        expect($result->context['exception'])->toBe($exception);

        $rendered = (new LineFormatter(includeStacktraces: true))->format($result);

        expect($rendered)->toContain('RuntimeException')
            ->and($rendered)->toContain('db down')
            ->and($rendered)->toContain('[stacktrace]');
    });

    it('passes dates, enums and closures through untouched', function (): void {
        $when = Date::parse('2026-09-13 10:00:00');
        $closure = fn (): int => 1;
        $zone = new \DateTimeZone('UTC');

        $result = resolve(Redactor::class)->redact([
            'when' => $when,
            'status' => OpaqueStatus::Active,
            'callback' => $closure,
            'zone' => $zone,
        ]);

        expect($result['when'])->toBe($when)
            ->and($result['status'])->toBe(OpaqueStatus::Active)
            ->and($result['callback'])->toBe($closure)
            ->and($result['zone'])->toBe($zone)
            ->and($result)->not->toHaveKey('_redacted');
    });

    it('still lets a key rule win over an opaque value', function (): void {
        $result = resolve(Redactor::class)->redact([
            'secret' => OpaqueStatus::Active,
            'password' => Date::now(),
        ]);

        expect($result['secret'])->toBe('[REDACTED]')
            ->and($result['password'])->toBe('[REDACTED]');
    });

    it('preserves an opaque object nested inside a structure that is otherwise redacted', function (): void {
        $exception = new \LogicException('nested');

        $result = resolve(Redactor::class)->redact([
            'user' => ['email' => 'bob@example.com', 'error' => $exception],
        ]);

        expect($result['user']['email'])->toBe('[REDACTED]')
            ->and($result['user']['error'])->toBe($exception);
    });

    it('raises no deprecation while walking objects', function (): void {
        $previous = set_error_handler(function (int $errno, string $errstr): bool {
            if (($errno & (E_DEPRECATED | E_USER_DEPRECATED)) !== 0) {
                throw new \ErrorException($errstr, 0, $errno);
            }

            return false;
        });

        try {
            $object = new \stdClass;
            $object->email = 'bob@example.com';
            $object->child = new \stdClass;
            $object->child->token = 'abc';

            $result = resolve(Redactor::class)->redact(['payload' => $object, 'other' => new \ArrayObject(['secret' => 'x'])]);

            expect($result['payload']['email'])->toBe('[REDACTED]');
        } finally {
            restore_error_handler();
        }
    });
});
