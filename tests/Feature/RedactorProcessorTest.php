<?php

declare(strict_types=1);

namespace Tests\Feature;

use Illuminate\Log\Logger;
use Kirschbaum\Redactor\Logging\ReadactFormatter;
use Kirschbaum\Redactor\Logging\RedactorProcessor;
use Kirschbaum\Redactor\Logging\RedactorTap;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Strategies\BlockedKeysStrategy;
use Monolog\DateTimeImmutable;
use Monolog\Formatter\JsonFormatter;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\Logger as MonologLogger;
use Monolog\LogRecord;
use Monolog\Processor\ProcessorInterface;

function logRecord(string $message, array $context = [], array $extra = []): LogRecord
{
    return new LogRecord(
        new DateTimeImmutable(true),
        'testing',
        Level::Info,
        $message,
        $context,
        $extra
    );
}

describe('RedactorProcessor', function () {
    it('is a Monolog processor', function () {
        expect(new RedactorProcessor(app(Redactor::class)))
            ->toBeInstanceOf(ProcessorInterface::class);
    });

    it('redacts the message and leaves the rest of the record intact', function () {
        $processor = new RedactorProcessor(app(Redactor::class));

        $result = $processor(logRecord('User bob@example.com signed in'));

        expect($result->message)->toBe('User [REDACTED] signed in')
            ->and($result->channel)->toBe('testing')
            ->and($result->level)->toBe(Level::Info);
    });

    it('redacts context', function () {
        $processor = new RedactorProcessor(app(Redactor::class));

        $result = $processor(logRecord('hi', ['password' => 'hunter2', 'keep' => 'visible']));

        expect($result->context['password'])->toBe('[REDACTED]')
            ->and($result->context['keep'])->toBe('visible');
    });

    it('redacts extra, which the formatter dropped entirely', function () {
        $processor = new RedactorProcessor(app(Redactor::class));

        $result = $processor(logRecord('hi', [], ['api_token' => 'abc123', 'pid' => 42]));

        expect($result->extra['api_token'])->toBe('[REDACTED]')
            ->and($result->extra['pid'])->toBe(42);
    });

    it('honours a profile override', function () {
        config()->set('redactor.profiles.tapped', [
            'enabled' => true,
            'strategies' => [BlockedKeysStrategy::class],
            'safe_keys' => [],
            'blocked_keys' => ['keep'],
            'patterns' => [],
            'replacement' => '<gone>',
            'mark_redacted' => false,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => ['enabled' => false],
        ]);

        $processor = new RedactorProcessor(app(Redactor::class), 'tapped');

        expect($processor(logRecord('hi', ['keep' => 'x']))->context['keep'])->toBe('<gone>');
    });

    it('never throws when the profile is broken', function () {
        $processor = new RedactorProcessor(app(Redactor::class), 'no_such_profile');

        $result = $processor(logRecord('bob@example.com', ['password' => 'hunter2']));

        expect($result->message)->not->toContain('bob@example.com')
            ->and(json_encode($result->context))->not->toContain('hunter2');
    });

    it('preserves the channel output format, unlike the formatter', function () {
        $monolog = new MonologLogger('testing');
        $handler = new TestHandler;
        $handler->setFormatter(new JsonFormatter);
        $monolog->pushHandler($handler);
        $monolog->pushProcessor(new RedactorProcessor(app(Redactor::class)));

        $monolog->info('User bob@example.com signed in', ['password' => 'hunter2']);

        $formatted = $handler->getRecords()[0]->formatted;

        expect(json_decode($formatted, true))->toBeArray()
            ->and($formatted)->not->toContain('bob@example.com')
            ->and($formatted)->not->toContain('hunter2');
    });
});

describe('RedactorTap', function () {
    it('adds the processor without replacing the formatter', function () {
        $monolog = new MonologLogger('testing');
        $handler = new TestHandler;
        $handler->setFormatter($json = new JsonFormatter);
        $monolog->pushHandler($handler);

        (new RedactorTap)(new Logger($monolog));

        expect($handler->getFormatter())->toBe($json)
            ->and($monolog->getProcessors()[0])->toBeInstanceOf(RedactorProcessor::class);
    });

    it('redacts records logged through the tapped channel', function () {
        $monolog = new MonologLogger('testing');
        $handler = new TestHandler;
        $monolog->pushHandler($handler);

        (new RedactorTap)(new Logger($monolog));

        $monolog->info('mail bob@example.com', ['password' => 'hunter2']);

        $record = $handler->getRecords()[0];

        expect($record->message)->toBe('mail [REDACTED]')
            ->and($record->context['password'])->toBe('[REDACTED]');
    });
});

describe('ReadactFormatter composition', function () {
    it('formats every record in a batch', function () {
        $formatter = new ReadactFormatter;

        $out = $formatter->formatBatch([
            logRecord('one'),
            logRecord('two'),
            logRecord('three'),
        ]);

        expect($out)->toContain('one')
            ->and($out)->toContain('two')
            ->and($out)->toContain('three')
            ->and(substr_count($out, "\n"))->toBe(3);
    });

    it('delegates to an inner formatter when given one', function () {
        $formatter = new ReadactFormatter(new JsonFormatter);

        $out = $formatter->format(logRecord('mail bob@example.com', ['password' => 'hunter2']));

        $decoded = json_decode($out, true);

        expect($decoded)->toBeArray()
            ->and($decoded['message'])->toBe('mail [REDACTED]')
            ->and($decoded['context']['password'])->toBe('[REDACTED]');
    });

    it('includes extra in its own output', function () {
        $formatter = new ReadactFormatter;

        $out = $formatter->format(logRecord('hi', [], ['pid' => 42]));

        expect($out)->toContain('"pid":42');
    });
});
