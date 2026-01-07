<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Config;

/**
 * Configuration for security middleware.
 */
final class SecurityConfig
{
    /**
     * @param bool $requireAuth Whether API key authentication is required
     * @param string[] $allowedScopes Scopes to allow (empty = all)
     * @param string $authHeader Header name for Bearer token
     * @param string $apiKeyHeader Alternative header for API key
     * @param string $scopesAttribute Request attribute name for storing scopes
     * @param string $keyAttribute Request attribute name for storing key info
     * @param bool $silentFail Return 404 instead of 401/403 (hide security rules)
     */
    public function __construct(
        public readonly bool $requireAuth = true,
        public readonly array $allowedScopes = [],
        public readonly string $authHeader = 'Authorization',
        public readonly string $apiKeyHeader = 'X-MCP-Api-Key',
        public readonly string $scopesAttribute = 'mcp.scopes',
        public readonly string $keyAttribute = 'mcp.key',
        public readonly bool $silentFail = false,
    ) {}
}
