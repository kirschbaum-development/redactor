<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\Detection\Confidence;
use Kirschbaum\Redactor\Detection\Detection;
use Kirschbaum\Redactor\Detection\Detector;
use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\Strategies\Contracts\DetectingStrategy;
use Kirschbaum\Redactor\Strategies\Contracts\Strategy;

/**
 * Finds the application's own credentials wherever they appear verbatim.
 *
 * Sources are the profile's `known_secrets` block, whose 'values' are literals
 * and whose 'config' entries are config keys read at build time, plus anything
 * registered at runtime with Redactor::registerSecret(). A value found this
 * way is certain: there is nothing to infer.
 */
class KnownSecretsStrategy implements DetectingStrategy, Detector, Strategy
{
    public const RULE = 'known_secret';

    /**
     * Determine if the value is long enough to contain a registered secret.
     */
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        return is_string($value) && $context->secrets()->couldContainOne($value);
    }

    /**
     * Collect every registered secret found in the value.
     */
    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        if (! is_string($value)) {
            return $value;
        }

        foreach ($this->detect($value, $key, $context) as $detection) {
            $context->collect($detection);
        }

        return $value;
    }

    /**
     * Get every occurrence of a registered secret in the subject.
     *
     * @return array<int, Detection>
     */
    public function detect(string $subject, string $key, RedactionContext $context): array
    {
        $detections = [];

        foreach ($context->secrets()->find($subject) as $hit) {
            $detections[] = new Detection(
                entity: $hit['entity'],
                rule: self::RULE,
                offset: $hit['offset'],
                value: $hit['value'],
                confidence: Confidence::of(Confidence::CERTAIN, 'a registered secret value appears verbatim'),
                key: $key,
            );
        }

        return $detections;
    }
}
