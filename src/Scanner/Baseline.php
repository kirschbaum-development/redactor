<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Scanner;

use JsonException;

/**
 * Accepted findings, so CI fails on new secrets rather than on known ones.
 *
 * Without this a repository with test fixtures - or a documented example key -
 * can never go green, which is the fastest way to get a scanner switched off.
 *
 * The file stores fingerprints only. A fingerprint is a hash of the rule, the
 * path and the secret, so accepting a finding does not commit the secret to
 * the repository, and moving the code around does not resurrect it.
 */
final class Baseline
{
    /**
     * @param  array<string, true>  $fingerprints
     */
    private function __construct(
        public readonly array $fingerprints,
        public readonly ?string $generatedAt = null,
    ) {}

    public static function empty(): self
    {
        return new self([]);
    }

    /**
     * @throws JsonException when the file exists but is not readable as a baseline
     */
    public static function load(string $path): self
    {
        if (! is_file($path)) {
            return self::empty();
        }

        $contents = @file_get_contents($path);

        if ($contents === false) {
            throw new JsonException("Baseline file [{$path}] could not be read.");
        }

        /** @var mixed $decoded */
        $decoded = json_decode($contents, true, 512, JSON_THROW_ON_ERROR);

        if (! is_array($decoded) || ! isset($decoded['findings']) || ! is_array($decoded['findings'])) {
            throw new JsonException("Baseline file [{$path}] is missing a \"findings\" array.");
        }

        $fingerprints = [];

        foreach ($decoded['findings'] as $entry) {
            if (is_string($entry)) {
                $fingerprints[$entry] = true;
            } elseif (is_array($entry) && isset($entry['fingerprint']) && is_string($entry['fingerprint'])) {
                $fingerprints[$entry['fingerprint']] = true;
            }
        }

        $generatedAt = $decoded['generated_at'] ?? null;

        return new self($fingerprints, is_string($generatedAt) ? $generatedAt : null);
    }

    /**
     * @param  array<int, ScanFinding>  $findings
     */
    public static function write(string $path, array $findings, string $generatedAt): bool
    {
        $entries = [];

        foreach ($findings as $finding) {
            // Path and rule are recorded for a human reading the diff; the
            // fingerprint is what is actually matched against.
            $entries[$finding->fingerprint] = [
                'fingerprint' => $finding->fingerprint,
                'rule' => $finding->rule,
                'path' => $finding->path,
            ];
        }

        ksort($entries);

        $json = json_encode([
            'version' => 1,
            'generated_at' => $generatedAt,
            'findings' => array_values($entries),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        if ($json === false) {
            return false;
        }

        return file_put_contents($path, $json."\n") !== false;
    }

    public function accepts(ScanFinding $finding): bool
    {
        return isset($this->fingerprints[$finding->fingerprint]);
    }

    public function isEmpty(): bool
    {
        return $this->fingerprints === [];
    }
}
