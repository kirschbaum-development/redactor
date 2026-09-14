<?php

declare(strict_types=1);

namespace Tests\Feature;

use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Support\Facades\Http;
use Kirschbaum\Redactor\Recognition\CircuitBreaker;
use Kirschbaum\Redactor\Recognition\RecognizedSpan;
use Kirschbaum\Redactor\Recognition\Recognizer;
use Kirschbaum\Redactor\Recognition\Recognizers\PresidioRecognizer;
use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\RedactorConfig;
use Kirschbaum\Redactor\Strategies\BlockedKeysStrategy;
use Kirschbaum\Redactor\Strategies\Contracts\PrimingStrategy;
use Kirschbaum\Redactor\Strategies\Contracts\Strategy;
use Kirschbaum\Redactor\Strategies\EntityRecognitionStrategy;
use Kirschbaum\Redactor\Strategies\LargeStringStrategy;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;
use Kirschbaum\Redactor\Strategies\SafeKeysStrategy;
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
        // Asked per value, since the batch driver already drops spans outside a text...
        config()->set('redactor.profiles.ner.recognition.batch', false);
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

describe('Entity recognition batching', function (): void {
    beforeEach(function (): void {
        CircuitBreaker::reset();
        config()->set('redactor.profiles.ner', nerProfile());
    });

    /** Answer one joined request by locating each name in the joined text. */
    function presidioFinding(array $names): callable
    {
        return function ($request) use ($names): PromiseInterface {
            $text = $request->data()['text'];
            $spans = [];

            foreach ($names as [$entity, $name, $score]) {
                $start = mb_strpos($text, $name);

                if ($start !== false) {
                    $spans[] = [$entity, $start, $start + mb_strlen($name), $score];
                }
            }

            return Http::response(presidio($spans));
        };
    }

    it('sends every prose value in one request and maps each span back to its own value', function (): void {
        Http::fake([NER_URL => presidioFinding([['PERSON', 'John Smith', 0.9], ['PERSON', 'Zoë Müller', 0.9], ['LOCATION', 'Berlin', 0.8]])]);

        $payload = [
            'notes' => 'Please call John Smith about the invoice',
            'nested' => [
                'summary' => 'Café visit with Zoë Müller went well today',
                'city' => 'She is now based in Berlin for the year',
            ],
            'count' => 3,
            'short' => 'no',
        ];

        $result = resolve(Redactor::class)->inspect($payload, 'ner');

        expect($result->value['notes'])->toBe('Please call [REDACTED] about the invoice')
            ->and($result->value['nested']['summary'])->toBe('Café visit with [REDACTED] went well today')
            ->and($result->value['nested']['city'])->toBe('She is now based in [REDACTED] for the year')
            ->and($result->value['count'])->toBe(3);

        Http::assertSentCount(1);
        Http::assertSent(fn ($request): bool => str_contains($request->data()['text'], "invoice\n\nCafé"));
    });

    it('sends identical texts once and leaves safe and blocked keys out of the batch', function (): void {
        config()->set('redactor.profiles.ner.safe_keys', ['public_note', 'public_notes']);
        config()->set('redactor.profiles.ner.blocked_keys', ['secret_note']);
        config()->set('redactor.profiles.ner.strategies', [
            SafeKeysStrategy::class,
            BlockedKeysStrategy::class,
            RegexPatternsStrategy::class,
            EntityRecognitionStrategy::class,
        ]);
        Http::fake([NER_URL => presidioFinding([['PERSON', 'John Smith', 0.9]])]);

        $payload = [
            'a' => 'Please call John Smith about the invoice',
            'b' => 'Please call John Smith about the invoice',
            'public_note' => 'Alice Jones wrote this public note for everyone',
            'secret_note' => 'Bob Brown wrote this private note for nobody',
            'public_notes' => ['Alice Jones wrote this public note for everyone too'],
        ];

        $result = resolve(Redactor::class)->inspect($payload, 'ner');

        expect($result->value['a'])->toBe('Please call [REDACTED] about the invoice')
            ->and($result->value['b'])->toBe('Please call [REDACTED] about the invoice')
            ->and($result->value['public_note'])->toBe('Alice Jones wrote this public note for everyone')
            ->and($result->value['secret_note'])->toBe('[REDACTED]');

        Http::assertSentCount(1);
        Http::assertSent(function ($request): bool {
            $text = $request->data()['text'];

            return substr_count($text, 'John Smith') === 1
                && ! str_contains($text, 'Alice Jones')
                && ! str_contains($text, 'Bob Brown');
        });
    });

    it('gathers prose from objects the way the walk opens them', function (): void {
        Http::fake([NER_URL => presidioFinding([['PERSON', 'John Smith', 0.9], ['PERSON', 'Jane Doe', 0.9]])]);

        $arrayable = new class implements Arrayable
        {
            public function toArray(): array
            {
                return ['note' => 'Please call John Smith about the invoice'];
            }
        };

        $plain = new \stdClass;
        $plain->note = 'Please call Jane Doe about the refund';

        // JSON cannot encode a self-reference, so this one is skipped, as the walk skips it...
        $unopenable = new \stdClass;
        $unopenable->self = $unopenable;
        $unopenable->note = 'Please call Bob Brown about the delivery';

        $payload = [
            'model' => $arrayable,
            'plain' => $plain,
            'unopenable' => $unopenable,
            'exception' => new RuntimeException('Please call John Smith about the invoice'),
            'when' => new \DateTimeImmutable('2024-01-01'),
        ];

        $result = resolve(Redactor::class)->inspect($payload, 'ner');

        expect($result->value['model']['note'])->toBe('Please call [REDACTED] about the invoice')
            ->and($result->value['plain']['note'])->toBe('Please call [REDACTED] about the refund');

        Http::assertSentCount(1);
        Http::assertSent(fn ($request): bool => ! str_contains($request->data()['text'], 'Bob Brown'));
    });

    it('stops gathering at the depth limit and on a cycle, like the walk', function (): void {
        Http::fake([NER_URL => presidioFinding([['PERSON', 'John Smith', 0.9], ['PERSON', 'Jane Smith', 0.9]])]);

        $cyclic = new class implements Arrayable
        {
            public function toArray(): array
            {
                return ['self' => $this, 'note' => 'Please call Jane Smith about the refund'];
            }
        };

        $payload = ['one' => ['two' => ['three' => 'Please call John Smith about the invoice']], 'cyclic' => $cyclic];

        // Deep enough for everything: the cycle is entered once and the deep value is found...
        resolve(Redactor::class)->inspect($payload, 'ner');

        Http::assertSent(fn ($request): bool => substr_count($request->data()['text'], 'Jane Smith') === 1
            && substr_count($request->data()['text'], 'John Smith') === 1);

        // Two levels: the deep value is never gathered...
        config()->set('redactor.profiles.ner.max_depth', 2);
        resolve(Redactor::class)->inspect($payload, 'ner');

        Http::assertSent(fn ($request): bool => ! str_contains($request->data()['text'], 'John Smith'));
    });

    it('counts a failed batch once and does not retry per value', function (): void {
        Http::fake([NER_URL => Http::response('down', 503)]);

        $payload = [
            'a' => 'Please call John Smith about the invoice',
            'b' => 'Please call Jane Doe about the refund',
            'c' => 'Please call Bob Brown about the delivery',
        ];

        $result = resolve(Redactor::class)->inspect($payload, 'ner');

        expect($result->value)->toBe($payload)
            ->and(CircuitBreaker::isOpen('presidio|ner'))->toBeFalse();

        Http::assertSentCount(1);
    });

    it('asks nothing while the breaker is open', function (): void {
        Http::fake([NER_URL => Http::response('down', 503)]);

        resolve(Redactor::class)->inspect(['a' => 'Please call John Smith about the invoice'], 'ner');
        resolve(Redactor::class)->inspect(['a' => 'Please call John Smith about the invoice'], 'ner');

        expect(CircuitBreaker::isOpen('presidio|ner'))->toBeTrue();

        resolve(Redactor::class)->inspect(['a' => 'Please call John Smith about the invoice'], 'ner');

        Http::assertSentCount(2);
    });

    it('counts a per-value failure against the breaker when batch is off', function (): void {
        config()->set('redactor.profiles.ner.recognition.batch', false);
        Http::fake([NER_URL => Http::response('down', 503)]);

        $result = resolve(Redactor::class)->inspect([
            'a' => 'Please call John Smith about the invoice',
            'b' => 'Please call John Smith about the refund',
        ], 'ner');

        expect($result->value['a'])->toBe('Please call John Smith about the invoice')
            ->and(CircuitBreaker::isOpen('presidio|ner'))->toBeTrue();

        Http::assertSentCount(2);
    });

    it('asks per value when batch is off', function (): void {
        config()->set('redactor.profiles.ner.recognition.batch', false);
        Http::fake([NER_URL => presidioFinding([['PERSON', 'John Smith', 0.9]])]);

        $result = resolve(Redactor::class)->inspect([
            'a' => 'Please call John Smith about the invoice',
            'b' => 'Please call John Smith about the refund',
        ], 'ner');

        expect($result->value['a'])->toBe('Please call [REDACTED] about the invoice')
            ->and($result->value['b'])->toBe('Please call [REDACTED] about the refund');

        Http::assertSentCount(2);
    });

    it('falls back to one call for a value the walk truncated before the strategy saw it', function (): void {
        config()->set('redactor.profiles.ner.max_value_length', 45);
        config()->set('redactor.profiles.ner.strategies', [
            LargeStringStrategy::class,
            RegexPatternsStrategy::class,
            EntityRecognitionStrategy::class,
        ]);
        Http::fake([NER_URL => presidioFinding([['PERSON', 'John Smith', 0.9]])]);

        $result = resolve(Redactor::class)->inspect([
            'a' => 'Please call John Smith about the invoice, the refund and the delivery schedule',
        ], 'ner');

        expect($result->value['a'])->toStartWith('Please call [REDACTED] about the invoice');

        Http::assertSentCount(2);
    });

    it('asks a recogniser that cannot take a list once per text, before the walk', function (): void {
        $redactor = resolve(Redactor::class);
        $calls = [];

        $redactor->registerRecognizer(new class($calls) implements Recognizer
        {
            public function __construct(private array &$calls) {}

            public function name(): string
            {
                return 'single';
            }

            public function recognize(string $text, string $language, array $entities, float $scoreThreshold): array
            {
                $this->calls[] = $text;

                return [new RecognizedSpan('PERSON', 12, 22, 0.9)];
            }
        });
        config()->set('redactor.profiles.ner.recognition.driver', 'single');

        $result = $redactor->inspect([
            'a' => 'Please call John Smith about the invoice',
            'b' => 'Please call Jane Smith about the refund',
        ], 'ner');

        expect($calls)->toBe(['Please call John Smith about the invoice', 'Please call Jane Smith about the refund'])
            ->and($result->value['a'])->toBe('Please call [REDACTED] about the invoice')
            ->and($result->value['b'])->toBe('Please call [REDACTED] about the refund');
    });

    it('skips the batch for an unknown driver and for a payload with no prose', function (): void {
        Http::fake();

        config()->set('redactor.profiles.ner.recognition.driver', 'missing');
        resolve(Redactor::class)->inspect(['a' => 'Please call John Smith about the invoice'], 'ner');

        config()->set('redactor.profiles.ner.recognition.driver', 'presidio');
        resolve(Redactor::class)->inspect(['a' => 'x', 'b' => 42], 'ner');

        Http::assertNothingSent();
    });
});

describe('PresidioRecognizer::recognizeMany', function (): void {
    it('drops a span that crosses the join between two texts', function (): void {
        // "Alice" ends text one; "Smith" starts text two; a span over both is an artefact...
        Http::fake([NER_URL => Http::sequence()
            ->push(presidio([['PERSON', 17, 29, 0.9]]))
            ->push(presidio([['PERSON', 17, 22, 0.9], ['PERSON', 24, 29, 0.9]]))]);

        $recognizer = new PresidioRecognizer(NER_URL);
        $spans = $recognizer->recognizeMany(['Please say hi to Alice', 'Smith is here now'], 'en', [], 0.5);

        expect($spans[0])->toHaveCount(0)
            ->and($spans[1])->toHaveCount(0);

        $spans = $recognizer->recognizeMany(['Please say hi to Alice', 'Smith is here now'], 'en', [], 0.5);

        expect($spans[0][0]->start)->toBe(17)
            ->and($spans[0][0]->end)->toBe(22)
            ->and($spans[1][0]->start)->toBe(0)
            ->and($spans[1][0]->end)->toBe(5);
    });

    it('splits texts into requests under the character cap', function (): void {
        Http::fake([NER_URL => Http::response([])]);

        $long = str_repeat('word ', 8000); // 40,000 characters
        $spans = (new PresidioRecognizer(NER_URL))->recognizeMany([$long, $long, 'short one here'], 'en', [], 0.5);

        expect($spans)->toHaveCount(3);

        Http::assertSentCount(2);
        Http::assertSent(fn ($request): bool => mb_strlen($request->data()['text']) <= PresidioRecognizer::BATCH_CHARACTERS);
    });

    it('keeps input indexes and returns an empty list for every text when nothing is found', function (): void {
        Http::fake([NER_URL => Http::response([])]);

        $spans = (new PresidioRecognizer(NER_URL))->recognizeMany([5 => 'Please say hi to Alice', 9 => 'Smith is here now'], 'en', [], 0.5);

        expect($spans)->toBe([5 => [], 9 => []]);
    });

    it('sends nothing for an empty list', function (): void {
        Http::fake();

        expect((new PresidioRecognizer(NER_URL))->recognizeMany([], 'en', [], 0.5))->toBe([]);

        Http::assertNothingSent();
    });
});

describe('Priming strategies', function (): void {
    it('see the whole payload once before the walk', function (): void {
        $seen = [];

        $strategy = new class($seen) implements PrimingStrategy
        {
            public function __construct(private array &$seen) {}

            public function prime(mixed $content, RedactionContext $context): void
            {
                $this->seen[] = $content;
            }

            public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
            {
                return false;
            }

            public function handle(mixed $value, string $key, RedactionContext $context): mixed
            {
                return $value;
            }
        };

        $redactor = resolve(Redactor::class);
        $redactor->registerCustomStrategy('primer', $strategy);
        config()->set('redactor.profiles.ner', nerProfile(['strategies' => ['primer']]));

        $redactor->redact(['a' => 1, 'b' => ['c' => 2]], 'ner');

        expect($seen)->toBe([['a' => 1, 'b' => ['c' => 2]]]);
    });
});
