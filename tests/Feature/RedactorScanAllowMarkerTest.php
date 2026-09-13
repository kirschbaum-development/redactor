<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Scanner\Scanner;

describe('Inline scan suppression', function () {
    beforeEach(function () {
        $this->path = tempnam(sys_get_temp_dir(), 'marker');
    });

    afterEach(fn () => @unlink($this->path));

    it('drops a finding on a line that carries the marker and keeps the others', function () {
        file_put_contents($this->path, implode("\n", [
            "\$fixture = 'sk_test_4eC39HqLyjWDarjtT1zdp7dc'; // redactor:allow",
            "\$real = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc';",
        ])."\n");

        $findings = app(Scanner::class)->scanFile($this->path, 'file_scan')->findings;

        expect($findings)->toHaveCount(1)
            ->and($findings[0]->line)->toBe(2);
    });

    it('leaves lines without the marker alone', function () {
        file_put_contents($this->path, "contact: bob@example.com\n");

        expect(app(Scanner::class)->scanFile($this->path, 'file_scan')->findings)->toHaveCount(1);
    });
});
