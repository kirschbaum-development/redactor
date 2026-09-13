<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Scanner\Decoding;

/**
 * Finds encoded spans in a window and recovers the text inside them.
 *
 * A secret in a repository is often not written plainly: a connection string
 * sits in a JSON file as `https:\/\/user:pass@host`, a key is base64-encoded
 * into a Kubernetes secret, a token is URL-encoded into a query string. None
 * of the plain patterns see through that, so the scanner decodes first and
 * scans what comes out, one layer deep. Redaction of live payloads does not
 * decode: it is a cost paid on every log line for a case that scanning is
 * the right place to catch.
 */
final class Decoder
{
    /**
     * Base64 tokens shorter than this are far more often ordinary words.
     */
    private const MIN_BASE64_LENGTH = 20;

    /**
     * @return array<int, DerivedSubject>
     */
    public static function derive(string $window): array
    {
        return [
            ...self::jsonEscaped($window),
            ...self::urlEncoded($window),
            ...self::base64($window),
        ];
    }

    /**
     * Lines with JSON string escapes, unescaped.
     *
     * `\/` is the one that matters most - json_encode() emits it by default,
     * so every credential URL in a JSON file carries it - but `\"` and
     * `\uXXXX` are handled the same way.
     *
     * @return array<int, DerivedSubject>
     */
    private static function jsonEscaped(string $window): array
    {
        if (! str_contains($window, '\\')) {
            return [];
        }

        $subjects = [];
        $offset = 0;

        foreach (explode("\n", $window) as $line) {
            $length = strlen($line);

            if (preg_match('/\\\\(?:[\/"\\\\bfnrt]|u[0-9a-fA-F]{4})/', $line) === 1) {
                $decoded = json_decode('"'.str_replace('"', '\\"', $line).'"');

                // Unescaping a backslash the line already escaped would have
                // doubled it; undo only what json_decode could interpret.
                if (is_string($decoded) && $decoded !== $line) {
                    $subjects[] = new DerivedSubject($decoded, $offset, $length, 'json');
                }
            }

            $offset += $length + 1;
        }

        return $subjects;
    }

    /**
     * Percent-encoded runs, decoded.
     *
     * @return array<int, DerivedSubject>
     */
    private static function urlEncoded(string $window): array
    {
        if (! str_contains($window, '%')) {
            return [];
        }

        if (preg_match_all('/[A-Za-z0-9_.~:\/?#@!$&\'()*+,;=%-]*(?:%[0-9A-Fa-f]{2})+[A-Za-z0-9_.~:\/?#@!$&\'()*+,;=%-]*/', $window, $matches, PREG_OFFSET_CAPTURE) === false) {
            return [];
        }

        $subjects = [];

        foreach ($matches[0] as [$encoded, $offset]) {
            $decoded = rawurldecode($encoded);

            if ($decoded !== $encoded) {
                $subjects[] = new DerivedSubject($decoded, (int) $offset, strlen($encoded), 'url');
            }
        }

        return $subjects;
    }

    /**
     * Base64 tokens that decode to printable text.
     *
     * @return array<int, DerivedSubject>
     */
    private static function base64(string $window): array
    {
        if (preg_match_all('/(?<![A-Za-z0-9+\/=])[A-Za-z0-9+\/]{'.self::MIN_BASE64_LENGTH.',}={0,2}(?![A-Za-z0-9+\/=])/', $window, $matches, PREG_OFFSET_CAPTURE) === false) {
            return [];
        }

        $subjects = [];

        foreach ($matches[0] as [$token, $offset]) {
            // A token of only letters or only digits is a word or a number.
            if (preg_match('/[A-Z]/', $token) !== 1 || preg_match('/[a-z]/', $token) !== 1 || preg_match('/[0-9+\/]/', $token) !== 1) {
                continue;
            }

            $decoded = base64_decode($token, true);

            if ($decoded === false || $decoded === '' || ! self::isText($decoded)) {
                continue;
            }

            $subjects[] = new DerivedSubject($decoded, (int) $offset, strlen($token), 'base64');
        }

        return $subjects;
    }

    /**
     * Whether decoded bytes are text worth scanning rather than a binary blob.
     */
    private static function isText(string $bytes): bool
    {
        if (str_contains($bytes, "\0") || ! mb_check_encoding($bytes, 'UTF-8')) {
            return false;
        }

        $printable = strlen((string) preg_replace('/[^\P{C}\n\r\t]/u', '', $bytes));

        return $printable >= strlen($bytes) * 0.9;
    }
}
