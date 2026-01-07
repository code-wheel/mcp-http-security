<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Tests\Config;

use CodeWheel\McpSecurity\Config\SecurityConfig;
use PHPUnit\Framework\TestCase;

final class SecurityConfigTest extends TestCase
{
    public function testDefaultValues(): void
    {
        $config = new SecurityConfig();

        $this->assertTrue($config->requireAuth);
        $this->assertSame([], $config->allowedScopes);
        $this->assertSame('Authorization', $config->authHeader);
        $this->assertSame('X-MCP-Api-Key', $config->apiKeyHeader);
        $this->assertSame('mcp.scopes', $config->scopesAttribute);
        $this->assertSame('mcp.key', $config->keyAttribute);
        $this->assertFalse($config->silentFail);
    }

    public function testCustomValues(): void
    {
        $config = new SecurityConfig(
            requireAuth: false,
            allowedScopes: ['read', 'write'],
            authHeader: 'X-Custom-Auth',
            apiKeyHeader: 'X-Custom-Key',
            scopesAttribute: 'custom.scopes',
            keyAttribute: 'custom.key',
            silentFail: true,
        );

        $this->assertFalse($config->requireAuth);
        $this->assertSame(['read', 'write'], $config->allowedScopes);
        $this->assertSame('X-Custom-Auth', $config->authHeader);
        $this->assertSame('X-Custom-Key', $config->apiKeyHeader);
        $this->assertSame('custom.scopes', $config->scopesAttribute);
        $this->assertSame('custom.key', $config->keyAttribute);
        $this->assertTrue($config->silentFail);
    }

    public function testPartialCustomization(): void
    {
        $config = new SecurityConfig(
            requireAuth: false,
            allowedScopes: ['admin'],
        );

        $this->assertFalse($config->requireAuth);
        $this->assertSame(['admin'], $config->allowedScopes);
        // Defaults for unspecified values
        $this->assertSame('Authorization', $config->authHeader);
        $this->assertSame('X-MCP-Api-Key', $config->apiKeyHeader);
    }

    public function testReadonlyProperties(): void
    {
        $config = new SecurityConfig();

        // Verify properties are readonly by checking each property
        $reflection = new \ReflectionClass($config);
        foreach ($reflection->getProperties() as $property) {
            $this->assertTrue($property->isReadOnly(), "Property {$property->getName()} should be readonly");
        }
    }
}
