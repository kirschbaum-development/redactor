<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Scanner;

/**
 * SARIF 2.1.0 output, so GitHub code scanning renders findings inline on the
 * pull request rather than leaving them in CI logs nobody opens.
 */
final class SarifReport
{
    private const SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';

    /**
     * @param  array<int, ScanFinding>  $findings
     * @return array<string, mixed>
     */
    public static function build(array $findings, string $version = '1.0.0'): array
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

            // Map the score onto SARIF's levels so a low-confidence hit shows
            // as a note rather than blocking a merge alongside a certain one.
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
                ], fn ($v) => $v !== null && $v !== '' && $v !== []),
                'locations' => [[
                    'physicalLocation' => [
                        'artifactLocation' => ['uri' => $finding->path],
                        'region' => [
                            'startLine' => max(1, $finding->line),
                            'startColumn' => max(1, $finding->column),
                            // The snippet comes from the redacted output, so a
                            // SARIF file can be uploaded without publishing the
                            // secret it reports.
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
                    ],
                ],
                'results' => $results,
            ]],
        ];
    }
}
