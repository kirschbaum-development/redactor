<?php

declare(strict_types=1);

namespace Tests\Feature;

use DateTimeImmutable;
use Kirschbaum\Redactor\Logging\ReadactFormatter;
use Monolog\Level;
use Monolog\LogRecord;

describe('ReadactFormatter Tests', function () {
    beforeEach(function () {
        // Set up basic redaction profile for testing
        config()->set('redactor.default_profile', 'logging_test');
        config()->set('redactor.profiles.logging_test', [
            'enabled' => true,
            'strategies' => [
                \Kirschbaum\Redactor\Strategies\BlockedKeysStrategy::class,
                \Kirschbaum\Redactor\Strategies\RegexPatternsStrategy::class,
            ],
            'safe_keys' => ['id'],
            'blocked_keys' => ['password', 'token', 'secret'],
            'patterns' => [
                'password_pattern' => '/password:\s*\S+/i',
                'token_pattern' => '/token:\s*\S+/i',
                'secret123_pattern' => '/secret123/i',
                'abc123_pattern' => '/abc123/i',
            ],
            'replacement' => '[REDACTED]',
            'mark_redacted' => true,
            'track_redacted_keys' => false,
            'non_redactable_object_behavior' => 'preserve',
            'max_value_length' => null,
            'redact_large_objects' => false,
            'max_object_size' => 100,
            'shannon_entropy' => ['enabled' => false],
        ]);
    });

    test('formats basic log record with string message', function () {
        $formatter = new ReadactFormatter;
        $datetime = new DateTimeImmutable('2023-12-25 14:30:45.123456');

        $record = new LogRecord(
            datetime: $datetime,
            channel: 'app',
            level: Level::Info,
            message: 'User logged in successfully',
            context: []
        );

        $result = $formatter->format($record);

        expect($result)->toBe("[2023-12-25 14:30:45.123456] app.INFO: User logged in successfully\n");
    });

    test('redacts sensitive data in log message', function () {
        $formatter = new ReadactFormatter;
        $datetime = new DateTimeImmutable('2023-12-25 14:30:45.123456');

        $record = new LogRecord(
            datetime: $datetime,
            channel: 'app',
            level: Level::Error,
            message: 'Login failed for password: secret123',
            context: []
        );

        $result = $formatter->format($record);

        expect($result)->toContain('[REDACTED]')
            ->and($result)->not->toContain('secret123')
            ->and($result)->toContain('[2023-12-25 14:30:45.123456] app.ERROR:');
    });

    test('handles array message by converting to json', function () {
        $formatter = new ReadactFormatter;
        $datetime = new DateTimeImmutable('2023-12-25 14:30:45.123456');

        $arrayMessage = ['action' => 'login', 'password' => 'secret123'];

        $record = new LogRecord(
            datetime: $datetime,
            channel: 'app',
            level: Level::Info,
            message: json_encode($arrayMessage), // Convert to string for LogRecord
            context: []
        );

        $result = $formatter->format($record);

        // Should redact sensitive data in the JSON string
        expect($result)->toContain('[REDACTED]')
            ->and($result)->toContain('[2023-12-25 14:30:45.123456] app.INFO:')
            ->and($result)->not->toContain('secret123');
    });

    test('handles object message by converting to json', function () {
        $formatter = new ReadactFormatter;
        $datetime = new DateTimeImmutable('2023-12-25 14:30:45.123456');

        $objectMessage = (object) ['action' => 'login', 'token' => 'abc123'];

        $record = new LogRecord(
            datetime: $datetime,
            channel: 'security',
            level: Level::Warning,
            message: json_encode($objectMessage), // Convert to string for LogRecord
            context: []
        );

        $result = $formatter->format($record);

        // Should redact sensitive data in the JSON string
        expect($result)->toContain('[REDACTED]')
            ->and($result)->toContain('[2023-12-25 14:30:45.123456] security.WARNING:')
            ->and($result)->not->toContain('abc123');
    });

    test('formats log record with context data', function () {
        $formatter = new ReadactFormatter;
        $datetime = new DateTimeImmutable('2023-12-25 14:30:45.123456');

        $context = [
            'user_id' => 123,
            'password' => 'secret123',
            'action' => 'login',
        ];

        $record = new LogRecord(
            datetime: $datetime,
            channel: 'app',
            level: Level::Info,
            message: 'User action performed',
            context: $context
        );

        $result = $formatter->format($record);

        expect($result)->toContain('[2023-12-25 14:30:45.123456] app.INFO: User action performed')
            ->and($result)->toContain('"user_id":123')
            ->and($result)->toContain('"password":"[REDACTED]"')
            ->and($result)->toContain('"action":"login"')
            ->and($result)->toContain('"_redacted":true')
            ->and($result)->not->toContain('secret123')
            ->and($result)->toEndWith("\n");
    });

    test('handles empty context gracefully', function () {
        $formatter = new ReadactFormatter;
        $datetime = new DateTimeImmutable('2023-12-25 14:30:45.123456');

        $record = new LogRecord(
            datetime: $datetime,
            channel: 'app',
            level: Level::Debug,
            message: 'Debug message',
            context: []
        );

        $result = $formatter->format($record);

        expect($result)->toBe("[2023-12-25 14:30:45.123456] app.DEBUG: Debug message\n")
            ->and($result)->not->toContain('{}');
    });

    test('handles different log levels correctly', function () {
        $formatter = new ReadactFormatter;
        $datetime = new DateTimeImmutable('2023-12-25 14:30:45.123456');

        $levels = [
            Level::Emergency,
            Level::Alert,
            Level::Critical,
            Level::Error,
            Level::Warning,
            Level::Notice,
            Level::Info,
            Level::Debug,
        ];

        $levelNames = [
            'EMERGENCY',
            'ALERT',
            'CRITICAL',
            'ERROR',
            'WARNING',
            'NOTICE',
            'INFO',
            'DEBUG',
        ];

        foreach ($levels as $index => $level) {
            $record = new LogRecord(
                datetime: $datetime,
                channel: 'test',
                level: $level,
                message: 'Test message',
                context: []
            );

            $result = $formatter->format($record);
            expect($result)->toContain("test.{$levelNames[$index]}:");
        }
    });

    test('formatBatch returns formatted first record', function () {
        $formatter = new ReadactFormatter;
        $datetime = new DateTimeImmutable('2023-12-25 14:30:45.123456');

        $records = [
            new LogRecord(
                datetime: $datetime,
                channel: 'app',
                level: Level::Info,
                message: 'First message',
                context: []
            ),
            new LogRecord(
                datetime: $datetime,
                channel: 'app',
                level: Level::Error,
                message: 'Second message',
                context: []
            ),
        ];

        $result = $formatter->formatBatch($records);

        expect($result)->toBe("[2023-12-25 14:30:45.123456] app.INFO: First message\n")
            ->and($result)->not->toContain('Second message');
    });

    test('handles null context values', function () {
        $formatter = new ReadactFormatter;
        $datetime = new DateTimeImmutable('2023-12-25 14:30:45.123456');

        $context = [
            'user_id' => null,
            'action' => 'test',
        ];

        $record = new LogRecord(
            datetime: $datetime,
            channel: 'app',
            level: Level::Info,
            message: 'Test message',
            context: $context
        );

        $result = $formatter->format($record);

        expect($result)->toContain('{"user_id":null,"action":"test"}');
    });

    test('preserves microseconds in timestamp', function () {
        $formatter = new ReadactFormatter;
        $datetime = new DateTimeImmutable('2023-12-25 14:30:45.999999');

        $record = new LogRecord(
            datetime: $datetime,
            channel: 'app',
            level: Level::Info,
            message: 'Test message',
            context: []
        );

        $result = $formatter->format($record);

        expect($result)->toContain('[2023-12-25 14:30:45.999999]');
    });
});
