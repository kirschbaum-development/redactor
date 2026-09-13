<?php

declare(strict_types=1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Http;
use Kirschbaum\Redactor\Recognition\CircuitBreaker;
use Kirschbaum\Redactor\Recognition\RecognizedSpan;
use Kirschbaum\Redactor\Recognition\Recognizer;
use Kirschbaum\Redactor\Recognition\Recognizers\PresidioRecognizer;
use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Strategies\Contracts\Strategy;
use Kirschbaum\Redactor\Strategies\EntityRecognitionStrategy;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;
use RuntimeException;

const NER_URL = 'http://presidio.test/analyze';

function nerProfile(array $overrides = []): array
{
    return array_merge([
        'enabled' => true,
        'strategies' => [RegexPatternsStrategy::class, EntityRecognitionStrategy::class],
        'safe_keys' => [],
        'blocked_keys' => [],
        'patterns' => ['email' => ['pattern' => '/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/', 'entity' => 'email']],
        'operators' => ['default' => 'redact'],
        'recognition' => [
            'enabled' => true,
            'driver' => 'presidio',
            'url' => NER_URL,
            'language' => 'en',
            'entities' => ['PERSON', 'LOCATION'],
            'entity_map' => ['PERSON' => 'person', 'LOCATION' => 'location'],
            'score_threshold' => 0.6,
            'min_length' => 10,
            'max_length' => 5000,
            'min_words' => 3,
            'timeout' => 1,
            'failure_threshold' => 2,
            'cooldown' => 60,
        ],
        'replacement' => '[REDACTED]',
        'mark_redacted' => false,
        'track_redacted_keys' => false,
        'non_redactable_object_behavior' => 'preserve',
        'max_value_length' => null,
        'redact_large_objects' => false,
        'max_object_size' => 100,
        'pseudonymization' => ['key' => testPseudonymizationKey()],
        'shannon_entropy' => ['enabled' => false],
    ], $overrides);
}

/** Presidio-shaped response for spans given as [entity, start, end, score]. */
function presidio(array $spans): array
{
    return array_map(fn (array $s): array => ['entity_type' => $s[0], 'start' => $s[1], 'end' => $s[2], 'score' => $s[3]], $spans);
}

describe('Entity recognition', function (): void {
    beforeEach(function (): void {
        CircuitBreaker::reset();
        config()->set('redactor.profiles.ner', nerProfile());
    });

    it('is off unless the profile enables it', function (): void {
        Http::fake();
        config()->set('redactor.profiles.ner.recognition.enabled', false);

        expect(resolve(Redactor::class)->redact('Please call John Smith about the invoice', 'ner'))
            ->toBe('Please call John Smith about the invoice');

        Http::assertNothingSent();
    });

    it('redacts a recognised person and goes through the entity operator', function (): void {
        Http::fake([NER_URL => Http::response(presidio([['PERSON', 12, 22, 0.85]]))]);
        config()->set('redactor.profiles.ner.operators', ['default' => 'redact', 'person' => 'hash']);

        $text = 'Please call John Smith about the invoice';

        expect(resolve(Redactor::class)->redact($text, 'ner'))
            ->toMatch('/^Please call \[person:[a-z0-9]+\] about the invoice$/');
    });

    it('sends the text, language, entities and threshold Presidio expects', function (): void {
        Http::fake([NER_URL => Http::response([])]);

        resolve(Redactor::class)->redact('Please call John Smith about the invoice', 'ner');

        Http::assertSent(fn ($request): bool => $request->url() === NER_URL
            && $request['text'] === 'Please call John Smith about the invoice'
            && $request['language'] === 'en'
            && $request['entities'] === ['PERSON', 'LOCATION']
            && $request['score_threshold'] === 0.6);
    });

    it('converts character offsets to bytes correctly after multibyte text', function (): void {
        // "Café " is 5 characters and 6 bytes; the name starts at character 5.
        $text = 'Café with Jürgen Müller yesterday';
        Http::fake([NER_URL => Http::response(presidio([['PERSON', 10, 23, 0.9]]))]);

        $result = resolve(Redactor::class)->inspect($text, 'ner');

        expect($result->value)->toBe('Café with [REDACTED] yesterday')
            ->and($result->findings[0]->matched)->toBe('Jürgen Müller')
            ->and($result->findings[0]->offset)->toBe(strlen('Café with '));
    });

    it('skips a span whose offsets do not land on the subject', function (): void {
        Http::fake([NER_URL => Http::response(presidio([['PERSON', 30, 60, 0.9], ['PERSON', 12, 22, 0.9]]))]);

        $text = 'Please call John Smith about the invoice';

        expect(resolve(Redactor::class)->redact($text, 'ner'))->toBe('Please call [REDACTED] about the invoice');
    });

    it('ignores labels the profile did not ask for and scores under the threshold', function (): void {
        Http::fake([NER_URL => Http::response(presidio([
            ['ORGANIZATION', 0, 6, 0.95],
            ['PERSON', 12, 22, 0.4],
            ['LOCATION', 33, 40, 0.7],
        ]))]);

        $text = 'Please call John Smith about the invoice';

        expect(resolve(Redactor::class)->redact($text, 'ner'))->toBe('Please call John Smith about the [REDACTED]');
    });

    it('works alongside the pattern detectors in one rewrite', function (): void {
        Http::fake([NER_URL => Http::response(presidio([['PERSON', 0, 10, 0.9]]))]);

        expect(resolve(Redactor::class)->redact('John Smith wrote to bob@example.com today', 'ner'))
            ->toBe('[REDACTED] wrote to [REDACTED] today');
    });

    it('does not ask the model about values that are not prose', function (): void {
        Http::fake();

        resolve(Redactor::class)->redact(['json' => '{"name":"John Smith","note":"call him"}', 'token' => 'Zx7Qm4Kd9Rb2Vn6Tp1Ws8Yc3Hf', 'short' => 'hi'], 'ner');

        Http::assertNothingSent();
    });

    it('never throws when the recogniser fails, and trips the breaker after repeated failures', function (): void {
        Http::fake([NER_URL => Http::response('down', 503)]);
        $text = 'Please call John Smith about the invoice';

        $redactor = resolve(Redactor::class);

        expect($redactor->redact($text, 'ner'))->toBe($text)
            ->and($redactor->redact($text, 'ner'))->toBe($text)
            ->and($redactor->redact($text, 'ner'))->toBe($text);

        // Threshold is 2: the third call is skipped without a request.
        Http::assertSentCount(2);
        expect(CircuitBreaker::isOpen('presidio|ner'))->toBeTrue();
    });

    it('closes the breaker again on success', function (): void {
        CircuitBreaker::recordFailure('presidio|ner', 1, 0);
        CircuitBreaker::recordSuccess('presidio|ner');

        expect(CircuitBreaker::allows('presidio|ner'))->toBeTrue();
    });

    it('accepts a recogniser registered at runtime', function (): void {
        $redactor = resolve(Redactor::class);
        $redactor->registerRecognizer(new class implements Recognizer
        {
            public function name(): string
            {
                return 'stub';
            }

            public function recognize(string $text, string $language, array $entities, float $scoreThreshold): array
            {
                return [new RecognizedSpan('PERSON', 12, 22, 0.99)];
            }
        });
        config()->set('redactor.profiles.ner.recognition.driver', 'stub');

        expect($redactor->redact('Please call John Smith about the invoice', 'ner'))
            ->toBe('Please call [REDACTED] about the invoice');
    });

    it('falls back to rules only for an unknown driver', function (): void {
        Http::fake();
        config()->set('redactor.profiles.ner.recognition.driver', 'nope');

        expect(resolve(Redactor::class)->redact('John Smith wrote to bob@example.com today', 'ner'))
            ->toBe('John Smith wrote to [REDACTED] today');
    });

    it('reports the recogniser and score in the finding', function (): void {
        Http::fake([NER_URL => Http::response(presidio([['PERSON', 12, 22, 0.85]]))]);

        $result = resolve(Redactor::class)->inspect('Please call John Smith about the invoice', 'ner');

        expect($result->findings[0]->rule)->toBe('entity_recognition')
            ->and($result->findings[0]->entity)->toBe('person')
            ->and($result->findings[0]->confidence?->score)->toBe(0.85)
            ->and(implode(' ', $result->findings[0]->confidence?->explain() ?? []))->toContain('presidio');
    });
});

describe('Conditional strategies', function (): void {
    it('leaves a disabled recognition strategy out of the chain and brings it back when enabled', function (): void {
        config()->set('redactor.profiles.ner', nerProfile(['recognition' => ['enabled' => false]]));
        $redactor = resolve(Redactor::class);

        $classes = fn (): array => array_map(fn (Strategy $s): string => $s::class, $redactor->strategies('ner'));

        expect($classes())->not->toContain(EntityRecognitionStrategy::class);

        config()->set('redactor.profiles.ner.recognition', nerProfile()['recognition']);

        expect($classes())->toContain(EntityRecognitionStrategy::class);
    });

    it('does not report a disabled strategy as unresolvable', function (): void {
        config()->set('redactor.profiles.ner', nerProfile(['recognition' => ['enabled' => false]]));

        expect(resolve(Redactor::class)->validateProfiles())->not->toHaveKey('ner');
    });
});

describe('Entity recognition at its edges', function (): void {
    beforeEach(function (): void {
        CircuitBreaker::reset();
        config()->set('redactor.profiles.ner', nerProfile());
    });

    it('skips a span that covers only whitespace', function (): void {
        Http::fake([NER_URL => Http::response(presidio([['PERSON', 11, 12, 0.9]]))]);
        $text = 'Please call John Smith about the invoice';

        $result = resolve(Redactor::class)->inspect($text, 'ner');

        expect($result->value)->toBe($text)
            ->and($result->findings)->toBe([]);
    });

    it('maps a label through entity_map, and falls back to the lowercased label when the map is not a map', function (): void {
        Http::fake([NER_URL => Http::response(presidio([['PERSON', 12, 22, 0.85]]))]);
        $text = 'Please call John Smith about the invoice';

        config()->set('redactor.profiles.ner.recognition.entity_map', ['PERSON' => 'customer']);
        $mapped = resolve(Redactor::class)->inspect($text, 'ner')->findings[0]->entity;

        config()->set('redactor.profiles.ner.recognition.entity_map', 'customer');
        $unmapped = resolve(Redactor::class)->inspect($text, 'ner')->findings[0]->entity;

        expect($mapped)->toBe('customer')
            ->and($unmapped)->toBe('person');
    });

    it('declines prose when the profile has recognition switched off, even when asked directly', function (): void {
        config()->set('redactor.profiles.ner.recognition.enabled', false);
        $context = new RedactionContext(RedactorConfig::fromConfig('ner'));

        expect((new EntityRecognitionStrategy)->shouldHandle('Please call John Smith about the invoice', 'k', $context))->toBeFalse();
    });

    it('rejects a Presidio body that is not a list', function (): void {
        Http::fake([NER_URL => Http::response('"just a string"', 200, ['Content-Type' => 'application/json'])]);

        expect(fn (): array => (new PresidioRecognizer(NER_URL, 1.0))->recognize('Please call John Smith', 'en', [], 0.5))
            ->toThrow(RuntimeException::class, 'non-list');
    });

    it('skips malformed Presidio items and keeps the well-formed ones', function (): void {
        Http::fake([NER_URL => Http::response([
            'nope',
            ['entity_type' => 'PERSON', 'start' => 'x', 'end' => 4, 'score' => 0.9],
            ['entity_type' => 'PERSON', 'start' => 12, 'end' => 22, 'score' => 0.9],
        ])]);

        $spans = (new PresidioRecognizer(NER_URL, 1.0))->recognize('Please call John Smith', 'en', ['PERSON'], 0.5);

        expect($spans)->toHaveCount(1)
            ->and($spans[0]->start)->toBe(12)
            ->and($spans[0]->end)->toBe(22);
    });

    it('exposes the recogniser registry with the built-in and anything registered since', function (): void {
        $redactor = resolve(Redactor::class);

        expect($redactor->recognizers()->has('presidio'))->toBeTrue()
            ->and($redactor->recognizers()->has('stub'))->toBeFalse();

        $redactor->registerRecognizer(new class implements Recognizer
        {
            public function name(): string
            {
                return 'stub';
            }

            public function recognize(string $text, string $language, array $entities, float $scoreThreshold): array
            {
                return [];
            }
        });

        expect($redactor->recognizers()->has('stub'))->toBeTrue();
    });
});
