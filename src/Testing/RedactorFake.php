<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Testing;

use Kirschbaum\Redactor\RedactionResult;
use Kirschbaum\Redactor\Redactor;
use PHPUnit\Framework\Assert;

/**
 * A redactor that remembers everything it was asked to do.
 *
 * Redaction is a runtime promise, and a promise nobody tests is one that
 * quietly stops being kept. Swap this in with Redactor::fake() and a test can
 * assert that a request's log line was redacted, that a given key was, and -
 * the one that matters most - that a known secret never appeared in anything
 * the redactor emitted, whichever profile and whichever path it took.
 *
 * It redacts for real; it just keeps the receipts.
 */
class RedactorFake extends Redactor
{
    /**
     * @var array<int, array{profile: string|null, input: mixed, result: RedactionResult}>
     */
    protected array $calls = [];

    public function redactWithMetadata(mixed $content, ?string $profile = null, ?bool $mark = null): RedactionResult
    {
        $result = parent::redactWithMetadata($content, $profile, $mark);

        $this->calls[] = ['profile' => $profile, 'input' => $content, 'result' => $result];

        return $result;
    }

    /**
     * Every call so far, oldest first.
     *
     * @return array<int, array{profile: string|null, input: mixed, result: RedactionResult}>
     */
    public function recorded(): array
    {
        return $this->calls;
    }

    public function forget(): void
    {
        $this->calls = [];
    }

    /**
     * None of the given values appeared in anything the redactor produced.
     *
     * The strongest thing a test can say about redaction: not "this key was
     * handled" but "this secret did not get out", across every call.
     */
    public function assertNeverEmitted(string ...$secrets): void
    {
        Assert::assertNotEmpty(
            $this->calls,
            'No redaction calls were recorded. Was the fake installed before the code under test resolved the redactor?'
        );

        foreach ($this->calls as $index => $call) {
            $output = self::stringify($call['result']->value);

            foreach ($secrets as $secret) {
                Assert::assertStringNotContainsString(
                    $secret,
                    $output,
                    sprintf('Call #%d (profile %s) emitted a value that should have been redacted.', $index + 1, $call['profile'] ?? 'default')
                );
            }
        }
    }

    /**
     * At least one call redacted something under this key.
     */
    public function assertRedacted(string $key): void
    {
        Assert::assertTrue(
            $this->anyCall(fn (RedactionResult $r) => in_array($key, $r->redactedKeys, true)),
            sprintf('No redaction recorded under key [%s]. Keys redacted: %s.', $key, $this->describeKeys())
        );
    }

    public function assertNotRedacted(string $key): void
    {
        Assert::assertFalse(
            $this->anyCall(fn (RedactionResult $r) => in_array($key, $r->redactedKeys, true)),
            sprintf('A redaction was recorded under key [%s], which should have been left alone.', $key)
        );
    }

    /**
     * At least one call produced a finding from this rule.
     */
    public function assertFinding(string $rule): void
    {
        Assert::assertTrue(
            $this->anyCall(function (RedactionResult $r) use ($rule): bool {
                foreach ($r->findings as $finding) {
                    if ($finding->rule === $rule) {
                        return true;
                    }
                }

                return false;
            }),
            sprintf('No finding from rule [%s] was recorded.', $rule)
        );
    }

    public function assertSomethingRedacted(): void
    {
        Assert::assertTrue(
            $this->anyCall(fn (RedactionResult $r) => $r->wasRedacted),
            'Nothing was redacted in any call.'
        );
    }

    public function assertNothingRedacted(): void
    {
        Assert::assertFalse(
            $this->anyCall(fn (RedactionResult $r) => $r->wasRedacted),
            sprintf('Something was redacted. Keys: %s.', $this->describeKeys())
        );
    }

    public function assertProfileUsed(string $profile): void
    {
        $used = array_values(array_unique(array_map(fn (array $c) => $c['profile'] ?? 'default', $this->calls)));

        Assert::assertContains(
            $profile,
            $used,
            sprintf('Profile [%s] was never used. Profiles used: %s.', $profile, $used === [] ? 'none' : implode(', ', $used))
        );
    }

    public function assertCalled(int $times): void
    {
        Assert::assertCount($times, $this->calls, sprintf('Expected %d redaction calls, recorded %d.', $times, count($this->calls)));
    }

    public function assertNotCalled(): void
    {
        $this->assertCalled(0);
    }

    /**
     * @param  callable(RedactionResult): bool  $predicate
     */
    private function anyCall(callable $predicate): bool
    {
        foreach ($this->calls as $call) {
            if ($predicate($call['result'])) {
                return true;
            }
        }

        return false;
    }

    private function describeKeys(): string
    {
        $keys = [];

        foreach ($this->calls as $call) {
            $keys = [...$keys, ...$call['result']->redactedKeys];
        }

        $keys = array_values(array_unique($keys));

        return $keys === [] ? 'none' : implode(', ', $keys);
    }

    private static function stringify(mixed $value): string
    {
        if (is_string($value)) {
            return $value;
        }

        $encoded = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR);

        return $encoded === false ? '' : $encoded;
    }
}
