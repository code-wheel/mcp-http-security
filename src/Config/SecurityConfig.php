<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Config;

/**
 * Configuration for security middleware.
 */
final readonly class SecurityConfig
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
        public bool $requireAuth = true,
        public array $allowedScopes = [],
        public string $authHeader = 'Authorization',
        public string $apiKeyHeader = 'X-MCP-Api-Key',
        public string $scopesAttribute = 'mcp.scopes',
        public string $keyAttribute = 'mcp.key',
        public bool $silentFail = false,
    ) {}
}
