<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Kirschbaum\Redactor\Scanner\Scanner;

describe('Scanning through encodings', function () {
    beforeEach(function () {
        config(['redactor.scan.profile' => 'file_scan', 'redactor.scan.baseline' => null]);
        $this->dir = sys_get_temp_dir().'/redactor_decode_'.uniqid();
        mkdir($this->dir);
    });

    afterEach(fn () => cleanupDirectory($this->dir));

    it('finds a credential URL hidden by JSON escaping', function () {
        file_put_contents($this->dir.'/config.json', json_encode(['db' => 'postgres://app:s3cr3t@db.internal/app']));

        $findings = app(Scanner::class)->scanFile($this->dir.'/config.json', 'file_scan')->findings;
        $rules = array_map(fn ($f) => $f->rule, $findings);

        expect($rules)->toContain('url_with_auth');

        $finding = $findings[array_search('url_with_auth', $rules, true)];

        expect($finding->encoding)->toBe('json')
            ->and($finding->line)->toBe(1)
            ->and($finding->excerpt)->toStartWith('[json]')
            ->and($finding->excerpt)->not->toContain('s3cr3t');
    });

    it('finds a key inside a base64 value, as in a Kubernetes secret', function () {
        $encoded = base64_encode('STRIPE_SECRET=sk_live_4eC39HqLyjWDarjtT1zdp7dc');
        file_put_contents($this->dir.'/secret.yml', "apiVersion: v1\nkind: Secret\ndata:\n  stripe: {$encoded}\n");

        $findings = app(Scanner::class)->scanFile($this->dir.'/secret.yml', 'file_scan')->findings;
        $stripe = array_values(array_filter($findings, fn ($f) => $f->rule === 'stripe_key'));

        expect($stripe)->toHaveCount(1)
            ->and($stripe[0]->encoding)->toBe('base64')
            ->and($stripe[0]->line)->toBe(4)
            ->and($stripe[0]->excerpt)->not->toContain('4eC39HqLyjWDarjtT1zdp7dc');
    });

    it('finds a token hidden by URL encoding', function () {
        file_put_contents($this->dir.'/access.log', 'GET /cb?next=https%3A%2F%2Fadmin%3Ahunter2%40db.example.com%2Fx HTTP/1.1'."\n");

        $findings = app(Scanner::class)->scanFile($this->dir.'/access.log', 'file_scan')->findings;

        expect(array_map(fn ($f) => [$f->rule, $f->encoding], $findings))->toContain(['url_with_auth', 'url']);
    });

    it('reports the encoding in JSON output and can be switched off', function () {
        file_put_contents($this->dir.'/config.json', json_encode(['db' => 'postgres://app:s3cr3t@db.internal/app']));

        Artisan::call('redactor:scan', ['paths' => [$this->dir], '--output' => 'json']);
        $with = json_decode(Artisan::output(), true)[0]['findings'];

        config(['redactor.scan.decode' => false]);
        app()->forgetInstance(Scanner::class);

        Artisan::call('redactor:scan', ['paths' => [$this->dir], '--output' => 'json']);
        $without = json_decode(Artisan::output(), true)[0]['findings'];

        expect(array_column($with, 'encoding'))->toContain('json')
            ->and(array_column($without, 'rule'))->not->toContain('url_with_auth');
    });
});
