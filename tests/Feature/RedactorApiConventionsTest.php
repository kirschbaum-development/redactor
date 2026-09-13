<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Exceptions\ConfigurationException;
use Kirschbaum\Redactor\Exceptions\GitException;
use Kirschbaum\Redactor\Exceptions\ProfileNotFoundException;
use Kirschbaum\Redactor\Exceptions\PseudonymizationKeyException;
use Kirschbaum\Redactor\Exceptions\RedactorException;
use Kirschbaum\Redactor\Facades\Redactor;
use Kirschbaum\Redactor\Findings\MatchFinding;
use Kirschbaum\Redactor\PendingRedaction;
use Kirschbaum\Redactor\RedactionResult;
use Kirschbaum\Redactor\Redactor as RedactorService;
use Kirschbaum\Redactor\Strategies\Contracts\Strategy;
use Kirschbaum\Redactor\Support\Pseudonymizer;

describe('Fluent entry point', function (): void {
    it('redacts with a chosen profile and no markers', function (): void {
        $result = Redactor::profile('default')->withoutMarkers()->redact(['password' => 'x', 'id' => 1]);

        expect($result)->toBe(['password' => '[REDACTED]', 'id' => 1]);
    });

    it('inspects', function (): void {
        $result = Redactor::profile('default')->inspect(['password' => 'x']);

        expect($result)->toBeInstanceOf(RedactionResult::class)
            ->and($result->redactedKeys)->toBe(['password']);
    });

    it('is conditionable and macroable', function (): void {
        PendingRedaction::macro('strictly', fn () => $this->profile('strict'));

        $pending = Redactor::profile('default')->when(true, fn (PendingRedaction $p) => $p->strictly());

        expect($pending)->toBeInstanceOf(PendingRedaction::class)
            ->and($pending->redact(['name' => 'Bob'])['name'])->toBe('[REDACTED]');
    });

    it('never throws from redactSafely', function (): void {
        expect(Redactor::profile('nope')->redactSafely(['password' => 'x']))->toBe('[REDACTED] (redaction failed)');
    });

    it('exposes inspect, profiles, hasProfile and strategies on the service', function (): void {
        expect(Redactor::inspect('a@b.com')->wasRedacted)->toBeTrue()
            ->and(Redactor::profiles())->toContain('default', 'strict')
            ->and(Redactor::hasProfile('default'))->toBeTrue()
            ->and(Redactor::hasProfile('nope'))->toBeFalse()
            ->and(Redactor::strategies('default'))->each->toBeInstanceOf(Strategy::class);
    });

    it('is macroable and conditionable itself', function (): void {
        RedactorService::macro('shout', fn (string $s): string => strtoupper($this->redact($s)));

        expect(Redactor::shout('hi a@b.com'))->toBe('HI [REDACTED]')
            ->and(resolve(RedactorService::class)->when(false, fn () => throw new \LogicException))->toBeInstanceOf(RedactorService::class);
    });
});

describe('Results are array-friendly', function (): void {
    it('serialises a result and its findings without the matched text', function (): void {
        $result = Redactor::inspect(['email' => 'bob@example.com']);

        $array = $result->toArray();

        expect($array['was_redacted'])->toBeTrue()
            ->and($array['findings'][0]['rule'])->toBe('blocked_key')
            ->and(json_encode($result))->not->toContain('bob@example.com')
            ->and(json_decode((string) json_encode($result), true)['redacted_keys'])->toBe(['email']);
    });
});

describe('Package exceptions', function (): void {
    it('throws a catchable package type for a missing profile', function (): void {
        try {
            Redactor::redact('x', 'nope');
        } catch (ProfileNotFoundException $e) {
            expect($e)->toBeInstanceOf(RedactorException::class)
                ->and($e)->toBeInstanceOf(ConfigurationException::class)
                ->and($e)->toBeInstanceOf(\InvalidArgumentException::class)
                ->and($e->getMessage())->toBe('Redaction profile [nope] is not configured.');

            return;
        }

        $this->fail('No exception thrown.');
    });

    it('throws a configuration exception for a bad value, still an InvalidArgumentException', function (): void {
        config()->set('redactor.profiles.default.max_depth', 'deep');

        expect(fn () => Redactor::redact('x'))->toThrow(ConfigurationException::class, 'max_depth');
    });

    it('throws a pseudonymization key exception for a short key', function (): void {
        expect(fn (): Pseudonymizer => Pseudonymizer::fromKey('short'))->toThrow(PseudonymizationKeyException::class);
    });

    it('marks git failures', function (): void {
        expect(new GitException('x'))->toBeInstanceOf(RedactorException::class);
    });
});

describe('Findings are JSON-friendly on their own', function (): void {
    it('serialises a finding the same way as toArray, without the matched text', function (): void {
        $finding = new MatchFinding(rule: 'email', key: 'contact', offset: 2, length: 3, matched: 'bob');

        expect(json_decode((string) json_encode($finding), true))->toBe($finding->toArray())
            ->and((string) json_encode($finding))->not->toContain('bob');
    });
});

describe('Markers through the fluent entry point', function (): void {
    it('writes the markers when asked, whatever the profile says', function (): void {
        config()->set('redactor.profiles.default.mark_redacted', false);

        $plain = Redactor::redact(['password' => 'hunter2']);
        $marked = Redactor::profile('default')->withMarkers()->redact(['password' => 'hunter2']);

        expect($plain)->not->toHaveKey('_redacted')
            ->and($marked['_redacted'])->toBeTrue();
    });
});
