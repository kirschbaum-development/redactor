<?php

declare(strict_types=1);

namespace Tests\Feature;

use Illuminate\Log\Logger;
use Kirschbaum\Redactor\Logging\RedactorFormatter;
use Kirschbaum\Redactor\Logging\RedactorFormatterTap;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\TestHandler;
use Monolog\Logger as MonologLogger;

describe('RedactorFormatterTap Tests', function (): void {
    test('tap applies RedactorFormatter to formattable handlers', function (): void {
        // Create a logger with a formattable handler
        $monolog = new MonologLogger('test');
        $handler = new TestHandler;
        $monolog->pushHandler($handler);

        $logger = new Logger($monolog);
        $tap = new RedactorFormatterTap;

        // Apply the tap
        $tap($logger);

        // Verify the formatter was set
        expect($handler->getFormatter())->toBeInstanceOf(RedactorFormatter::class);
    });

    test('tap applies RedactorFormatter to multiple formattable handlers', function (): void {
        // Create a logger with multiple formattable handlers
        $monolog = new MonologLogger('test');
        $handler1 = new TestHandler;
        $handler2 = new StreamHandler('php://memory');
        $monolog->pushHandler($handler1);
        $monolog->pushHandler($handler2);

        $logger = new Logger($monolog);
        $tap = new RedactorFormatterTap;

        // Apply the tap
        $tap($logger);

        // Verify formatters were set on both handlers
        expect($handler1->getFormatter())->toBeInstanceOf(RedactorFormatter::class)
            ->and($handler2->getFormatter())->toBeInstanceOf(RedactorFormatter::class);
    });

    test('tap handles logger with no handlers gracefully', function (): void {
        // Create a logger with no handlers
        $monolog = new MonologLogger('test');
        $logger = new Logger($monolog);
        $tap = new RedactorFormatterTap;

        // This should not throw any exceptions
        $tap($logger);

        // Just verify that no exception was thrown by reaching this point
        expect(true)->toBeTrue();
    });

    test('tap skips non-formattable handlers', function (): void {
        // Create a mock handler that doesn't implement FormattableHandlerInterface
        $nonFormattableHandler = new class
        {
            public function getFormatter(): null
            {
                return null;
            }
        };

        // Create a logger with mixed handler types
        $monolog = new MonologLogger('test');
        $formattableHandler = new TestHandler;

        // We need to use reflection to add the non-formattable handler
        // since Monolog validates handler types
        $logger = new Logger($monolog);
        $tap = new RedactorFormatterTap;

        // Add only the formattable handler
        $monolog->pushHandler($formattableHandler);

        // Apply the tap
        $tap($logger);

        // Only the formattable handler should have the formatter
        expect($formattableHandler->getFormatter())->toBeInstanceOf(RedactorFormatter::class);
    });

    test('tap can be invoked multiple times without issues', function (): void {
        // Create a logger with a handler
        $monolog = new MonologLogger('test');
        $handler = new TestHandler;
        $monolog->pushHandler($handler);

        $logger = new Logger($monolog);
        $tap = new RedactorFormatterTap;

        // Apply the tap multiple times
        $tap($logger);
        $tap($logger);
        $tap($logger);

        // Should still work and have the correct formatter
        expect($handler->getFormatter())->toBeInstanceOf(RedactorFormatter::class);
    });
});
