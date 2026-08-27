<?php

declare(strict_types=1);

namespace Tests\Feature;

use Kirschbaum\Redactor\Operators\OperatorSpec;
use Kirschbaum\Redactor\Path\PathPattern;
use Kirschbaum\Redactor\Path\PathTrie;
use Kirschbaum\Redactor\Redactor;
use Kirschbaum\Redactor\Strategies\BlockedKeysStrategy;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;

function pathProfile(array $paths, array $overrides = []): array
{
    return array_merge([
        'enabled' => true,
        'strategies' => [BlockedKeysStrategy::class, RegexPatternsStrategy::class],
        'safe_keys' => [],
        'blocked_keys' => [],
        'patterns' => [],
        'paths' => $paths,
        'operators' => ['default' => 'redact'],
        'replacement' => '[REDACTED]',
        'mark_redacted' => false,
        'track_redacted_keys' => false,
        'non_redactable_object_behavior' => 'preserve',
        'max_value_length' => null,
        'redact_large_objects' => false,
        'max_object_size' => 100,
        'shannon_entropy' => ['enabled' => false],
        'pseudonymization' => ['enabled' => true, 'key' => testPseudonymizationKey()],
    ], $overrides);
}

function redactPath(array $paths, array $payload, array $overrides = []): array
{
    config()->set('redactor.profiles.paths', pathProfile($paths, $overrides));

    $result = app(Redactor::class)->redact($payload, 'paths');

    return is_array($result) ? $result : [];
}

describe('Path matching', function () {
    it('matches an exact path and nothing else', function () {
        $result = redactPath(
            ['request.headers.authorization' => 'redact'],
            [
                'request' => ['headers' => ['authorization' => 'Bearer abc', 'accept' => 'json']],
                'authorization' => 'top level, different place',
            ],
        );

        expect($result['request']['headers']['authorization'])->toBe('[REDACTED]')
            ->and($result['request']['headers']['accept'])->toBe('json')
            // A key rule for "authorization" would have caught this too. A path
            // rule is precise about where, which is the point.
            ->and($result['authorization'])->toBe('top level, different place');
    });

    it('matches a single level with *', function () {
        $result = redactPath(
            ['user.*.email' => 'redact'],
            ['user' => [
                'primary' => ['email' => 'a@b.com'],
                'billing' => ['email' => 'c@d.com'],
                'deep' => ['nested' => ['email' => 'e@f.com']],
            ]],
        );

        expect($result['user']['primary']['email'])->toBe('[REDACTED]')
            ->and($result['user']['billing']['email'])->toBe('[REDACTED]')
            // One level, not any level.
            ->and($result['user']['deep']['nested']['email'])->toBe('e@f.com');
    });

    it('matches any depth with **', function () {
        $result = redactPath(
            ['**.password' => 'redact'],
            [
                'password' => 'top',
                'a' => ['password' => 'one deep'],
                'b' => ['c' => ['d' => ['password' => 'four deep']]],
                'keep' => 'visible',
            ],
        );

        expect($result['password'])->toBe('[REDACTED]')
            ->and($result['a']['password'])->toBe('[REDACTED]')
            ->and($result['b']['c']['d']['password'])->toBe('[REDACTED]')
            ->and($result['keep'])->toBe('visible');
    });

    it('lets ** match zero segments', function () {
        $result = redactPath(
            ['a.**.secret' => 'redact'],
            ['a' => ['secret' => 'immediately below a']],
        );

        expect($result['a']['secret'])->toBe('[REDACTED]');
    });

    it('walks through lists with either spelling', function () {
        $bracket = redactPath(['users[*].token' => 'redact'], [
            'users' => [['token' => 'one'], ['token' => 'two']],
        ]);

        $dotted = redactPath(['users.*.token' => 'redact'], [
            'users' => [['token' => 'one'], ['token' => 'two']],
        ]);

        expect($bracket['users'][0]['token'])->toBe('[REDACTED]')
            ->and($bracket['users'][1]['token'])->toBe('[REDACTED]')
            ->and($dotted)->toBe($bracket);
    });

    it('matches path segments case-insensitively', function () {
        $result = redactPath(
            ['request.headers.authorization' => 'redact'],
            ['Request' => ['Headers' => ['Authorization' => 'Bearer abc']]],
        );

        expect($result['Request']['Headers']['Authorization'])->toBe('[REDACTED]');
    });

    it('leaves a payload with no matching path completely alone', function () {
        $payload = ['a' => ['b' => 'value'], 'c' => 'other'];

        expect(redactPath(['x.y.z' => 'redact'], $payload))->toBe($payload);
    });
});

describe('Path precedence', function () {
    it('prefers the more specific pattern regardless of declaration order', function () {
        $specificLast = redactPath(
            ['**.token' => 'redact', 'auth.token' => ['partial' => ['keep' => 4]]],
            ['auth' => ['token' => 'abcdefgh']],
        );

        $specificFirst = redactPath(
            ['auth.token' => ['partial' => ['keep' => 4]], '**.token' => 'redact'],
            ['auth' => ['token' => 'abcdefgh']],
        );

        expect($specificLast['auth']['token'])->toBe('****efgh')
            ->and($specificFirst['auth']['token'])->toBe('****efgh');
    });

    it('beats a key rule that would otherwise fire', function () {
        // The key rule says redact anything called token; the path rule carves
        // out one location and keeps it.
        $result = redactPath(
            ['public.token' => 'preserve'],
            ['public' => ['token' => 'not-a-secret'], 'private' => ['token' => 'secret']],
            ['blocked_keys' => ['*token*']],
        );

        expect($result['public']['token'])->toBe('not-a-secret')
            ->and($result['private']['token'])->toBe('[REDACTED]');
    });

    it('stops the walk at the matched node', function () {
        // The path names a whole subtree, so nothing beneath it is inspected.
        $result = redactPath(
            ['debug' => 'preserve'],
            ['debug' => ['password' => 'kept', 'nested' => ['token' => 'kept too']]],
            ['blocked_keys' => ['password', '*token*']],
        );

        expect($result['debug'])->toBe(['password' => 'kept', 'nested' => ['token' => 'kept too']]);
    });
});

describe('Path operators', function () {
    it('supports the full operator range on a scalar', function () {
        $payload = ['a' => ['v' => 'abcdefgh']];

        expect(redactPath(['a.v' => 'mask'], $payload)['a']['v'])->toBe('********')
            ->and(redactPath(['a.v' => ['partial' => ['keep' => 3]]], $payload)['a']['v'])->toBe('*****fgh')
            ->and(redactPath(['a.v' => 'preserve'], $payload)['a']['v'])->toBe('abcdefgh');
    });

    it('drops the key entirely under remove', function () {
        $result = redactPath(['a.gone' => 'remove'], ['a' => ['gone' => 'x', 'kept' => 'y']]);

        expect($result['a'])->toBe(['kept' => 'y']);
    });

    it('pseudonymises at a path', function () {
        $result = redactPath(['user.email' => 'surrogate'], ['user' => ['email' => 'alice@customer.com']]);

        expect($result['user']['email'])->toEndWith('@customer.com')
            ->and($result['user']['email'])->not->toContain('alice');
    });

    it('replaces a whole subtree when the operator has no meaning for a container', function () {
        // Masking an array has no defensible behaviour, so the subtree is
        // replaced rather than a behaviour being invented for it.
        $result = redactPath(['a.b' => 'mask'], ['a' => ['b' => ['x' => 1, 'y' => 2]]]);

        expect($result['a']['b'])->toBe('[REDACTED]');
    });

    it('reports the pattern that fired', function () {
        config()->set('redactor.profiles.paths', pathProfile(
            ['request.headers.authorization' => 'redact'],
            ['track_redacted_keys' => true, 'mark_redacted' => true],
        ));

        $result = app(Redactor::class)->redactWithMetadata(
            ['request' => ['headers' => ['authorization' => 'Bearer abc']]],
            'paths',
        );

        expect($result->wasRedacted)->toBeTrue()
            ->and($result->findings[0]->rule)->toBe('path:request.headers.authorization');
    });
});

describe('Compiled state invalidates on config change', function () {
    it('rebuilds the trie when a path rule is added', function () {
        $before = redactPath(['a.one' => 'redact'], ['a' => ['one' => 'x', 'two' => 'y']]);

        expect($before['a'])->toBe(['one' => '[REDACTED]', 'two' => 'y']);

        $after = redactPath(['a.one' => 'redact', 'a.two' => 'redact'], ['a' => ['one' => 'x', 'two' => 'y']]);

        expect($after['a'])->toBe(['one' => '[REDACTED]', 'two' => '[REDACTED]']);
    });

    it('rebuilds when only the operator changes', function () {
        // Same pattern, different verb. A cache keyed on patterns alone would
        // serve the old operator and the config change would silently not
        // apply - the failure mode that turns a cache into a security bug.
        $redacted = redactPath(['a.v' => 'redact'], ['a' => ['v' => 'abcdefgh']]);
        $masked = redactPath(['a.v' => 'mask'], ['a' => ['v' => 'abcdefgh']]);

        expect($redacted['a']['v'])->toBe('[REDACTED]')
            ->and($masked['a']['v'])->toBe('********');
    });

    it('rebuilds when only an operator option changes', function () {
        $keepFour = redactPath(['a.v' => ['partial' => ['keep' => 4]]], ['a' => ['v' => 'abcdefgh']]);
        $keepTwo = redactPath(['a.v' => ['partial' => ['keep' => 2]]], ['a' => ['v' => 'abcdefgh']]);

        expect($keepFour['a']['v'])->toBe('****efgh')
            ->and($keepTwo['a']['v'])->toBe('******gh');
    });

    it('rebuilds the profile when an unrelated setting changes', function () {
        $first = redactPath(['a.v' => 'redact'], ['a' => ['v' => 'x']]);

        expect($first['a']['v'])->toBe('[REDACTED]');

        $second = redactPath(['a.v' => 'redact'], ['a' => ['v' => 'x']], ['replacement' => '<GONE>']);

        expect($second['a']['v'])->toBe('<GONE>');
    });

    it('rebuilds when the profile is disabled', function () {
        expect(redactPath(['a.v' => 'redact'], ['a' => ['v' => 'x']])['a']['v'])->toBe('[REDACTED]');

        config()->set('redactor.profiles.paths', pathProfile(['a.v' => 'redact'], ['enabled' => false]));

        expect(app(Redactor::class)->redact(['a' => ['v' => 'x']], 'paths'))->toBe(['a' => ['v' => 'x']]);
    });
});

describe('Path compilation', function () {
    it('normalises the two list spellings to the same segments', function () {
        expect(PathPattern::parse('users[*].email')->segments)
            ->toBe(PathPattern::parse('users.*.email')->segments);
    });

    it('scores literals above single wildcards above deep wildcards', function () {
        $literal = PathPattern::parse('a.b.c')->specificity;
        $single = PathPattern::parse('a.*.c')->specificity;
        $deep = PathPattern::parse('a.**.c')->specificity;

        expect($literal)->toBeGreaterThan($single)
            ->and($single)->toBeGreaterThan($deep);
    });

    it('rejects an empty pattern', function () {
        expect(fn () => PathPattern::parse('...'))
            ->toThrow(\InvalidArgumentException::class);
    });

    it('reports an empty trie as empty, and never matches', function () {
        $trie = PathTrie::compile([]);

        expect($trie->isEmpty())->toBeTrue()
            ->and($trie->cursor()->isExhausted())->toBeTrue()
            ->and($trie->cursor()->descend('anything')->match())->toBeNull();
    });

    it('exhausts the cursor once no rule can still match', function () {
        $trie = PathTrie::compile(['a.b' => new OperatorSpec('redact')]);

        expect($trie->cursor()->descend('a')->isExhausted())->toBeFalse()
            ->and($trie->cursor()->descend('z')->isExhausted())->toBeTrue();
    });

    it('keeps a deep-wildcard cursor alive at every level', function () {
        $trie = PathTrie::compile(['**.secret' => new OperatorSpec('redact')]);

        $cursor = $trie->cursor()->descend('a')->descend('b')->descend('c');

        expect($cursor->isExhausted())->toBeFalse()
            ->and($cursor->descend('secret')->match())->not->toBeNull();
    });
});
