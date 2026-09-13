<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Scanner\Baseline;

describe('Ruleset fingerprint', function () {
    beforeEach(function () {
        config(['redactor.scan.profile' => 'file_scan', 'redactor.scan.baseline' => null]);
        $this->dir = sys_get_temp_dir().'/redactor_ruleset_'.uniqid();
        mkdir($this->dir);
        file_put_contents($this->dir.'/app.env', "KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc\n");
    });

    afterEach(fn () => cleanupDirectory($this->dir));

    it('is stable for the same rules and changes when a rule changes', function () {
        $before = RedactorConfig::fromConfig('file_scan')->rulesetFingerprint;

        expect($before)->toHaveLength(16)
            ->and(RedactorConfig::fromConfig('file_scan')->rulesetFingerprint)->toBe($before);

        config()->set('redactor.profiles.file_scan.patterns.extra', '/x-\d+/');

        expect(RedactorConfig::fromConfig('file_scan')->rulesetFingerprint)->not->toBe($before);
    });

    it('is carried in JSON and SARIF output', function () {
        $expected = RedactorConfig::fromConfig('file_scan')->rulesetFingerprint;

        Artisan::call('redactor:scan', ['paths' => [$this->dir], '--output' => 'json']);
        expect(json_decode(Artisan::output(), true)[0]['ruleset'])->toBe($expected);

        Artisan::call('redactor:scan', ['paths' => [$this->dir], '--output' => 'sarif']);
        expect(json_decode(Artisan::output(), true)['runs'][0]['tool']['driver']['properties']['rulesetFingerprint'])->toBe($expected);
    });

    it('is written into the baseline and a mismatch is warned about', function () {
        $baseline = $this->dir.'/baseline.json';

        Artisan::call('redactor:scan', ['paths' => [$this->dir], '--baseline' => $baseline, '--update-baseline' => true]);

        expect(Baseline::load($baseline)->ruleset)->toBe(RedactorConfig::fromConfig('file_scan')->rulesetFingerprint);

        Artisan::call('redactor:scan', ['paths' => [$this->dir], '--baseline' => $baseline]);
        expect(Artisan::output())->not->toContain('generated under ruleset');

        config()->set('redactor.profiles.file_scan.patterns.extra', '/x-\d+/');

        Artisan::call('redactor:scan', ['paths' => [$this->dir], '--baseline' => $baseline]);
        expect(Artisan::output())->toContain('generated under ruleset');
    });
});
