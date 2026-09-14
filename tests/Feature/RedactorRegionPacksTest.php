<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Exceptions\ConfigurationException;
use Kirschbaum\Redactor\Facades\Redactor;
use Kirschbaum\Redactor\Findings\MatchFinding;
use Kirschbaum\Redactor\Patterns\Validator;

describe('Region packs', function (): void {
    it('are off unless a profile lists them', function (): void {
        expect(Redactor::redact('NI AB123456C'))->toBe('NI AB123456C');
    });

    it('redact every sample of every pack once switched on, and leave every counter-sample alone', function (): void {
        $packs = config('redactor.regions');
        config()->set('redactor.profiles.default.regions', array_keys($packs));

        foreach ($packs as $region => $rules) {
            foreach ($rules as $name => $rule) {
                foreach ($rule['samples'] as $sample) {
                    $findings = Redactor::inspect($sample)->findings;

                    expect(in_array($name, array_map(fn (MatchFinding $f): string => $f->rule, $findings), true))->toBeTrue("{$region}: {$name} missed {$sample}");
                }

                foreach ($rule['counter_samples'] as $sample) {
                    $findings = Redactor::inspect($sample)->findings;

                    expect(in_array($name, array_map(fn (MatchFinding $f): string => $f->rule, $findings), true))->toBeFalse("{$region}: {$name} matched {$sample}");
                }
            }
        }
    });

    it('validate cleanly as a whole', function (): void {
        config()->set('redactor.profiles.default.regions', array_keys(config('redactor.regions')));

        expect(resolve(\Kirschbaum\Redactor\Redactor::class)->validateProfiles())->toBe([]);
    });

    it('leave ordinary log text alone with every pack on', function (): void {
        config()->set('redactor.profiles.default.regions', array_keys(config('redactor.regions')));

        foreach ([
            'started at 1694600000 and 2026-09-14 10:00:00',
            'order 1234567890 ref 987654321',
            'version v10.2.100 build 20260914',
            'request 550e8400-e29b-41d4-a716-446655440000',
        ] as $line) {
            expect(Redactor::inspect($line)->wasRedacted)->toBeFalse($line);
        }
    });

    it('carry the entity through to operators', function (): void {
        config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        config()->set('redactor.profiles.default.regions', ['gb']);
        config()->set('redactor.profiles.default.operators', ['default' => 'redact', 'national_id' => 'hash']);

        expect(Redactor::redact('NI AB123456C'))->toMatch('/^NI \[national_id:[a-z0-9]+\]$/');
    });

    it('let a profile rule of the same name win', function (): void {
        config()->set('redactor.profiles.default.regions', ['gb']);
        config()->set('redactor.profiles.default.patterns.uk_vat', '/never-matches-anything-xyz/');

        expect(Redactor::redact('VAT GB436083107'))->toBe('VAT GB436083107');
    });

    it('name an unknown region', function (): void {
        config()->set('redactor.profiles.default.regions', ['atlantis']);

        expect(fn () => Redactor::redact('x'))->toThrow(ConfigurationException::class, 'atlantis');
    });

    it('accept a validator registered at runtime', function (): void {
        Validator::extend('starts_with_z', fn (string $v): bool => str_starts_with($v, 'Z'));
        config()->set('redactor.profiles.default.patterns.zed', ['pattern' => '/\b[A-Z]\d{4}\b/', 'validator' => 'starts_with_z']);

        expect(Redactor::redact('Z1234 and A1234'))->toBe('[REDACTED] and A1234');
    });

    it('reject an unknown validator name with the known ones listed', function (): void {
        config()->set('redactor.profiles.default.patterns.bad', ['pattern' => '/x/', 'validator' => 'mystery']);

        expect(fn () => Redactor::redact('x'))->toThrow(ConfigurationException::class, 'luhn');
    });
});
