<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;

function samplesProfile(array $patterns): array
{
    return [
        'enabled' => true,
        'strategies' => [RegexPatternsStrategy::class],
        'safe_keys' => [],
        'blocked_keys' => [],
        'patterns' => $patterns,
        'replacement' => '[REDACTED]',
        'mark_redacted' => false,
        'track_redacted_keys' => false,
        'non_redactable_object_behavior' => 'preserve',
        'max_value_length' => null,
        'redact_large_objects' => false,
        'max_object_size' => 100,
        'shannon_entropy' => ['enabled' => false],
    ];
}

describe('Rules that carry their own samples', function () {
    it('passes when every sample is detected and no counter-sample is', function () {
        config()->set('redactor.profiles.sampled', samplesProfile([
            'order' => ['pattern' => '/\bORD-\d{6}\b/', 'samples' => ['ref ORD-123456'], 'counter_samples' => ['ORD-12']],
        ]));

        expect(app(Redactor::class)->validateProfiles())->not->toHaveKey('sampled');
    });

    it('fails a rule that no longer detects its sample, naming both', function () {
        config()->set('redactor.profiles.sampled', samplesProfile([
            'order' => ['pattern' => '/\bORD-\d{6}\b/', 'samples' => ['ref ORD-12']],
        ]));

        $errors = app(Redactor::class)->validateProfiles();

        expect($errors['sampled'])->toContain('"order"')
            ->and($errors['sampled'])->toContain('does not detect its sample')
            ->and($errors['sampled'])->toContain('ORD-12');
    });

    it('fails a rule that detects a counter-sample', function () {
        config()->set('redactor.profiles.sampled', samplesProfile([
            'digits' => ['pattern' => '/\d+/', 'counter_samples' => ['started at 1694600000']],
        ]));

        expect(app(Redactor::class)->validateProfiles()['sampled'])->toContain('detects its counter-sample');
    });

    it('checks samples through the real detection path, keywords and validators included', function () {
        config()->set('redactor.profiles.sampled', samplesProfile([
            'card' => ['pattern' => '/\b\d{16}\b/', 'validator' => 'luhn', 'samples' => ['1234567890123456']],
            'phone' => ['pattern' => '/\b\d{10}\b/', 'keywords' => ['phone'], 'samples' => ['5558675309']],
        ]));

        $errors = app(Redactor::class)->validateProfiles()['sampled'];

        expect($errors)->toContain('"card"')
            ->and($errors)->toContain('"phone"');
    });

    it('reports every failing sample, not just the first', function () {
        config()->set('redactor.profiles.sampled', samplesProfile([
            'a' => ['pattern' => '/aaa/', 'samples' => ['bbb']],
            'b' => ['pattern' => '/bbb/', 'samples' => ['aaa']],
        ]));

        $errors = app(Redactor::class)->validateProfiles()['sampled'];

        expect($errors)->toContain('"a"')->and($errors)->toContain('"b"');
    });

    it('surfaces the failure through redactor:validate', function () {
        config()->set('redactor.profiles.sampled', samplesProfile([
            'order' => ['pattern' => '/\bORD-\d{6}\b/', 'samples' => ['nothing here']],
        ]));

        $this->artisan('redactor:validate')
            ->expectsOutputToContain('does not detect its sample')
            ->assertFailed();
    });

    it('ships every profile with samples that pass', function () {
        expect(app(Redactor::class)->validateProfiles())->toBe([]);

        $rules = RedactorConfig::fromConfig('default')->patterns;
        $withSamples = array_filter($rules, fn ($r) => $r->samples !== []);

        expect(count($withSamples))->toBe(count($rules));
    });
});
