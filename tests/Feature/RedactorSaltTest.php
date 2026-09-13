<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Redactor;

describe('Pseudonymisation salt', function () {
    beforeEach(function () {
        config()->set('redactor.pseudonymization.key', testPseudonymizationKey());
        config()->set('redactor.profiles.channel_a', config('redactor.profiles.observability'));
        config()->set('redactor.profiles.channel_b', config('redactor.profiles.observability'));
    });

    it('produces the same surrogate for the same value on every profile', function () {
        $a = app(Redactor::class)->redact('alice@customer.com', 'channel_a');
        $b = app(Redactor::class)->redact('alice@customer.com', 'channel_b');

        expect($a)->toMatch('/^u_[a-z0-9]+@customer\.com$/')
            ->and($b)->toBe($a);
    });

    it('lets a profile break the correlation with its own salt', function () {
        config()->set('redactor.profiles.channel_b.pseudonymization', ['salt' => 'export-only']);

        $a = app(Redactor::class)->redact('alice@customer.com', 'channel_a');
        $b = app(Redactor::class)->redact('alice@customer.com', 'channel_b');

        expect($b)->toMatch('/^u_[a-z0-9]+@customer\.com$/')
            ->and($b)->not->toBe($a);
    });

    it('changes every surrogate when the global salt changes', function () {
        $before = app(Redactor::class)->redact('alice@customer.com', 'channel_a');

        config()->set('redactor.pseudonymization.salt', 'rotated');

        expect(app(Redactor::class)->redact('alice@customer.com', 'channel_a'))->not->toBe($before);
    });
});
