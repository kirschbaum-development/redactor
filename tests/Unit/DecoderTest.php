<?php

declare(strict_types=1);

use Kirschbaum\Redactor\Scanner\Decoding\Decoder;
use Kirschbaum\Redactor\Scanner\Decoding\DerivedSubject;

describe('Decoder', function (): void {
    it('unescapes a JSON line and reports the line span', function (): void {
        $window = "{\n  \"db\": \"postgres:\\/\\/app:s3cr3t@db\\/x\"\n}";

        $derived = Decoder::derive($window);

        expect($derived)->toHaveCount(1)
            ->and($derived[0]->encoding)->toBe('json')
            ->and($derived[0]->text)->toContain('postgres://app:s3cr3t@db/x')
            ->and($derived[0]->offset)->toBe(2)
            ->and(substr($window, $derived[0]->offset, $derived[0]->length))->toStartWith('  "db"');
    });

    it('decodes a base64 token that holds text and skips words and binaries', function (): void {
        $secret = base64_encode('STRIPE=sk_live_4eC39HqLyjWDarjtT1zdp7dc');
        $binary = base64_encode(random_bytes(30));
        $window = "data:\n  key: {$secret}\n  blob: {$binary}\n  word: Authorization\n";

        $derived = Decoder::derive($window);
        $base64 = array_values(array_filter($derived, fn (DerivedSubject $d): bool => $d->encoding === 'base64'));

        expect($base64)->toHaveCount(1)
            ->and($base64[0]->text)->toBe('STRIPE=sk_live_4eC39HqLyjWDarjtT1zdp7dc')
            ->and(substr($window, $base64[0]->offset, $base64[0]->length))->toBe($secret);
    });

    it('decodes a percent-encoded run', function (): void {
        $window = 'GET /cb?token=sk_live_4eC39HqLyjWDarjtT1zdp7dc%26redirect%3Dhttps%3A%2F%2Fu%3Ap%40h';

        $derived = Decoder::derive($window);
        $url = array_values(array_filter($derived, fn (DerivedSubject $d): bool => $d->encoding === 'url'));

        expect($url)->not->toBeEmpty()
            ->and($url[0]->text)->toContain('https://u:p@h');
    });

    it('derives nothing from plain text', function (): void {
        expect(Decoder::derive("just a line\nand another\n"))->toBe([]);
    });
});
