<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Redactor;

/**
 * What the shipped profiles catch in ordinary log text, and what they leave
 * alone. Every line here is the shape of something that appears in a real
 * Laravel log; the misses and the false positives were both found by probing
 * the default profile with exactly these values.
 */
function shippedSecrets(): array
{
    return [
        'jwt' => 'auth failed for token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
        'aws_access_key' => 'using key AKIAIOSFODNN7EXAMPLE for s3',
        'github_token' => 'pushed with ghp_16C7e42F292c6912E7710c838347Ae178B4a',
        'github_fine_grained' => 'github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123',
        'stripe_key' => 'charged via sk_live_4eC39HqLyjWDarjtT1zdp7dc',
        'slack_token' => 'posted with xoxb-1234567890-abcdefghijABCDEFGHIJ',
        'openai_key' => 'model call with sk-proj-abcdefghijklmnopqrstuvwxyz0123',
        'anthropic_key' => 'model call with sk-ant-api03-abcdefghijklmnopqrstuvwxyz',
        'google_api_key' => 'maps with AIzaSyA1234567890abcdefghijklmnopqrstuv',
        'sendgrid_key' => 'mail via SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ',
        'bearer' => 'Authorization: Bearer 8f14e45fceea167a5a36dedd4bea2543',
        'private_key' => "cert -----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY----- end",
        'email' => 'user bob@example.com signed in',
        'unicode_email' => 'user josé@münchen.de signed in',
        'iban_spaced' => 'refund to DE89 3704 0044 0532 0130 00 please',
        'iban_compact' => 'refund to DE89370400440532013000 please',
        'phone_intl' => 'call +44 20 7946 0958 now',
        'phone_us' => 'call +1 (555) 867-5309 now',
        'phone_e164' => 'call +447946095800 now',
        'phone_labelled' => 'Phone: 5558675309',
        'card' => 'paid with 4111111111111111 ok',
        'ssn' => 'ssn 123-45-6789 on file',
    ];
}

function shippedInnocents(): array
{
    return [
        'unix_timestamp' => 'job started at 1694600000 and finished at 1694600123',
        'order_number' => 'order 1234567890 for customer 987654321',
        'date_time' => 'at 2026-09-13 10:00:00 the job ran',
        'version' => 'running v10.2.100 on php 8.5.8',
        'money' => 'total 1,234.56 charged',
        'invalid_card' => 'ref 1234567890123456 is not a card',
        'invalid_ssn' => 'code 000-12-3456 is not an ssn',
        'uuid' => 'request 550e8400-e29b-41d4-a716-446655440000 done',
        'prose' => 'the quick brown fox jumps over the lazy dog',
        'path' => 'wrote /var/www/html/storage/logs/laravel.log',
    ];
}

describe('Shipped profiles catch credentials in free text', function (): void {
    foreach (['default', 'strict', 'observability', 'file_scan'] as $profile) {
        it("catches every planted secret with the {$profile} profile", function () use ($profile): void {
            config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));

            foreach (shippedSecrets() as $name => $line) {
                $result = resolve(Redactor::class)->inspect($line, $profile);

                expect($result->wasRedacted)->toBeTrue("{$profile} missed {$name}: {$line}");
            }
        });
    }

    it('keeps the host and path of a credential URL for any scheme', function (): void {
        $result = resolve(Redactor::class)->redact('db at postgres://app:s3cr3t@db.internal:5432/app');

        expect($result)->toBe('db at postgres://app:[REDACTED]@db.internal:5432/app');
    });

    it('replaces only the token after Bearer', function (): void {
        expect(resolve(Redactor::class)->redact('Authorization: Bearer 8f14e45fceea167a5a36dedd4bea2543'))
            ->toBe('Authorization: Bearer [REDACTED]');
    });

    it('prefers the more specific provider rule when two prefixes overlap', function (): void {
        $result = resolve(Redactor::class)->inspect('sk-ant-api03-abcdefghijklmnopqrstuvwxyz');

        expect($result->findings)->toHaveCount(1)
            ->and($result->findings[0]->rule)->toBe('anthropic_key');
    });
});

describe('Shipped profiles leave ordinary log text alone', function (): void {
    foreach (['default', 'observability', 'performance'] as $profile) {
        it("does not touch any innocent line with the {$profile} profile", function () use ($profile): void {
            foreach (shippedInnocents() as $name => $line) {
                $result = resolve(Redactor::class)->inspect($line, $profile);

                expect($result->wasRedacted)->toBeFalse("{$profile} redacted {$name}: ".json_encode($result->value));
            }
        });
    }

    it('does not mistake a card number for a formatted phone number', function (): void {
        // Partial masking keeps the length, spaces included: 15 masked, 4 kept.
        expect(resolve(Redactor::class)->redact('paid with 4111 1111 1111 1111 ok'))
            ->toBe('paid with ***************1111 ok');
    });

    it('believes a bare ten-digit run only next to a label', function (): void {
        expect(resolve(Redactor::class)->redact('Phone: 5558675309'))->toBe('Phone: [REDACTED]')
            ->and(resolve(Redactor::class)->redact('id 5558675309'))->toBe('id 5558675309');
    });
});

describe('The performance profile', function (): void {
    it('still catches an email and a bare token but is gated on literals', function (): void {
        expect(resolve(Redactor::class)->redact('user bob@example.com', 'performance'))->toBe('user [REDACTED]')
            ->and(resolve(Redactor::class)->redact(['t' => str_repeat('Ab1', 12)], 'performance'))->toBe(['t' => '[REDACTED]']);
    });
});
