<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\RedactionContext;
use Kirschbaum\Redactor\Strategies\Contracts\Strategy;

/**
 * Replaces a container with more items than the profile allows.
 */
class LargeObjectStrategy implements Strategy
{
    /**
     * Determine if the value has more items than the profile allows.
     */
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        $maxObjectSize = $context->config->maxObjectSize;

        if (! $context->config->redactLargeObjects || $maxObjectSize === null) {
            return false;
        }

        if (is_array($value)) {
            return count($value) > $maxObjectSize;
        }

        if (is_object($value)) {
            // Objects are measured through toArray() when they offer it...
            if (method_exists($value, 'toArray')) {
                try {
                    $array = $value->toArray();

                    return is_array($array) && count($array) > $maxObjectSize;
                } catch (\Throwable) {
                    return false;
                }
            }

            // Otherwise estimate the size through a JSON round trip...
            try {
                $jsonString = json_encode($value, JSON_THROW_ON_ERROR);
                $array = json_decode($jsonString, true, 512, JSON_THROW_ON_ERROR);

                return is_array($array) && count($array) > $maxObjectSize;
            } catch (\Throwable) {
                return false;
            }
        }

        return false;
    }

    /**
     * Replace the value with a summary of what it held.
     */
    public function handle(mixed $value, string $key, RedactionContext $context): mixed
    {
        $context->markRedacted();

        if (is_array($value)) {
            return [
                '_large_object_redacted' => sprintf(
                    '%s (Array with %d items)',
                    $context->config->replacement,
                    count($value)
                ),
            ];
        }

        if (is_object($value)) {
            // Count the properties for the message where the object allows it...
            $propertyCount = 'large number of';
            try {
                if (method_exists($value, 'toArray')) {
                    $array = $value->toArray();
                    if (is_array($array)) {
                        $propertyCount = (string) count($array);
                    }
                } else {
                    $jsonString = json_encode($value, JSON_THROW_ON_ERROR);
                    $array = json_decode($jsonString, true, 512, JSON_THROW_ON_ERROR);
                    if (is_array($array)) {
                        $propertyCount = (string) count($array);
                    }
                }
            } catch (\Throwable) {
                // Keep the default message...
            }

            return [
                '_large_object_redacted' => sprintf(
                    '%s (Object %s with %s properties)',
                    $context->config->replacement,
                    $value::class,
                    $propertyCount
                ),
            ];
        }

        return $value;
    }
}
