<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Validation;

/**
 * Validates request origins/hostnames against an allowlist.
 *
 * Supports:
 * - Exact matches: example.com
 * - Wildcard subdomains: *.example.com (matches foo.example.com but not example.com)
 */
final class OriginValidator
{
    /**
     * @param string[] $allowedOrigins Allowed hostnames/patterns
     */
    public function __construct(
        private readonly array $allowedOrigins = [],
    ) {}

    /**
     * Check if hostname is allowed.
     *
     * Returns true if:
     * - No allowlist configured (empty = allow all)
     * - Hostname matches allowlist
     */
    public function isAllowed(string $hostname): bool
    {
        if (empty($this->allowedOrigins)) {
            return true;
        }

        $hostname = strtolower(trim($hostname));
        if ($hostname === '') {
            return false;
        }

        foreach ($this->allowedOrigins as $pattern) {
            if ($this->matchesPattern($hostname, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Extract hostname from Origin, Referer, or Host header value.
     *
     * @param string $value Header value (can be URL or hostname)
     */
    public function extractHostname(string $value): ?string
    {
        $value = trim($value);
        if ($value === '') {
            return null;
        }

        // If it looks like a URL, parse it
        if (preg_match('/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//', $value)) {
            $host = parse_url($value, PHP_URL_HOST);
            return is_string($host) && $host !== '' ? strtolower($host) : null;
        }

        // Try adding a scheme and parsing
        $host = parse_url('http://' . $value, PHP_URL_HOST);
        return is_string($host) && $host !== '' ? strtolower($host) : null;
    }

    private function matchesPattern(string $hostname, string $pattern): bool
    {
        $pattern = strtolower(trim((string) $pattern));
        if ($pattern === '') {
            return false;
        }

        // Exact match
        if ($hostname === $pattern) {
            return true;
        }

        // Wildcard subdomain: *.example.com
        if (str_starts_with($pattern, '*.')) {
            $suffix = substr($pattern, 1); // .example.com
            if ($suffix !== '' && str_ends_with($hostname, $suffix)) {
                // Make sure it's a subdomain, not the root
                $root = ltrim($suffix, '.');
                return $hostname !== $root;
            }
        }

        return false;
    }
}
