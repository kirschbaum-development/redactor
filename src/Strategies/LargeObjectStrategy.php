<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Strategies;

use Kirschbaum\Redactor\RedactionContext;

class LargeObjectStrategy implements RedactionStrategyInterface
{
    public function shouldHandle(mixed $value, string $key, RedactionContext $context): bool
    {
        if (! $context->config->redactLargeObjects) {
            return false;
        }

        if (is_array($value)) {
            return count($value) > $context->config->maxObjectSize;
        }

        if (is_object($value)) {
            // For objects, we'll need to check if they can be converted to array first
            if (method_exists($value, 'toArray')) {
                try {
                    $array = $value->toArray();

                    return is_array($array) && count($array) > $context->config->maxObjectSize;
                } catch (\Throwable) {
                    return false;
                }
            }

            // Try JSON encoding to get a size estimate
            try {
                $jsonString = json_encode($value, JSON_THROW_ON_ERROR);
                $array = json_decode($jsonString, true, 512, JSON_THROW_ON_ERROR);

                return is_array($array) && count($array) > $context->config->maxObjectSize;
            } catch (\Throwable) {
                return false;
            }
        }

        return false;
    }

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
            // Try to get property count for more accurate messaging
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
                // Keep default message
            }

            return [
                '_large_object_redacted' => sprintf(
                    '%s (Object %s with %s properties)',
                    $context->config->replacement,
                    get_class($value),
                    $propertyCount
                ),
            ];
        }

        return $value;
    }
}
