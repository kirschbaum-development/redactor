<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Scanner;

/**
 * JUnit XML, so a CI dashboard that already renders test results renders
 * scan findings too: one test case per scanned file, one failure per finding.
 */
class JunitReport
{
    /**
     * @param  array<int, ScanResult>  $results
     */
    public static function build(array $results): string
    {
        $failures = 0;
        $cases = '';

        foreach ($results as $result) {
            $cases .= sprintf('    <testcase name="%s" classname="redactor.scan">'."\n", self::escape($result->path));

            if ($result->skipped) {
                $cases .= sprintf('      <skipped message="%s"/>'."\n", self::escape($result->error ?? 'skipped'));
            }

            foreach ($result->findings as $finding) {
                $failures++;
                $cases .= sprintf(
                    '      <failure message="%s" type="%s">%s</failure>'."\n",
                    self::escape(sprintf('%s at %s:%d:%d (%s)', $finding->rule, $finding->path, $finding->line, $finding->column, $finding->severity())),
                    self::escape($finding->rule),
                    self::escape($finding->excerpt)
                );
            }

            $cases .= "    </testcase>\n";
        }

        $count = count($results);

        return '<?xml version="1.0" encoding="UTF-8"?>'."\n"
            .sprintf('<testsuites name="redactor" tests="%d" failures="%d">'."\n", $count, $failures)
            .sprintf('  <testsuite name="redactor:scan" tests="%d" failures="%d">'."\n", $count, $failures)
            .$cases
            ."  </testsuite>\n"
            ."</testsuites>\n";
    }

    private static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_XML1 | ENT_QUOTES, 'UTF-8');
    }
}
