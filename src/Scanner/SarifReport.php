<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Scanner;

/**
 * SARIF 2.1.0 output, so GitHub code scanning renders findings inline on the
 * pull request rather than leaving them in CI logs nobody opens.
 */
class SarifReport
{
    private const string SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';

    /**
     * @param  array<int, ScanFinding>  $findings
     * @return array<string, mixed>
     */
    public static function build(array $findings, string $version = '1.0.0', ?string $ruleset = null): array
    {
        $rules = [];
        $results = [];

        foreach ($findings as $finding) {
            $rules[$finding->rule] ??= [
                'id' => $finding->rule,
                'name' => $finding->rule,
                'shortDescription' => ['text' => sprintf('Potential secret detected by rule "%s"', $finding->rule)],
                'defaultConfiguration' => ['level' => 'error'],
            ];

            // Map the score onto SARIF's levels so a low-confidence hit is a note, not a merge blocker...
            $level = match ($finding->severity()) {
                'high' => 'error',
                'medium' => 'warning',
                default => 'note',
            };

            $results[] = [
                'ruleId' => $finding->rule,
                'level' => $level,
                'message' => ['text' => sprintf(
                    'Sensitive content matched rule "%s"%s.',
                    $finding->rule,
                    $finding->confidence === null ? '' : sprintf(' (confidence %.2f)', $finding->confidence)
                )],
                'partialFingerprints' => ['redactorFingerprint/v1' => $finding->fingerprint],
                'properties' => array_filter([
                    'entity' => $finding->entity,
                    'confidence' => $finding->confidence,
                    'signals' => $finding->signals,
                ], fn (string|float|array|null $v): bool => ! in_array($v, [null, '', []], true)),
                'locations' => [[
                    'physicalLocation' => [
                        'artifactLocation' => ['uri' => $finding->path],
                        'region' => [
                            'startLine' => max(1, $finding->line),
                            'startColumn' => max(1, $finding->column),
                            // The snippet is redacted output, so the file can be uploaded without the secret...
                            'snippet' => ['text' => $finding->excerpt],
                        ],
                    ],
                ]],
            ];
        }

        return [
            '$schema' => self::SCHEMA,
            'version' => '2.1.0',
            'runs' => [[
                'tool' => [
                    'driver' => [
                        'name' => 'Redactor',
                        'informationUri' => 'https://github.com/kirschbaum-development/redactor',
                        'version' => $version,
                        'rules' => array_values($rules),
                        // Record which rules produced these results so two runs can be compared...
                        'properties' => array_filter(['rulesetFingerprint' => $ruleset]),
                    ],
                ],
                'results' => $results,
            ]],
        ];
    }
}
