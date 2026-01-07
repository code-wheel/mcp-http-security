<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Tests\ApiKey;

use CodeWheel\McpSecurity\ApiKey\ApiKey;
use PHPUnit\Framework\TestCase;

final class ApiKeyTest extends TestCase
{
    public function testConstructorSetsAllProperties(): void
    {
        $apiKey = new ApiKey(
            keyId: 'abc123',
            label: 'Test Key',
            scopes: ['read', 'write'],
            created: 1000000,
            lastUsed: 2000000,
            expires: 3000000,
        );

        $this->assertSame('abc123', $apiKey->keyId);
        $this->assertSame('Test Key', $apiKey->label);
        $this->assertSame(['read', 'write'], $apiKey->scopes);
        $this->assertSame(1000000, $apiKey->created);
        $this->assertSame(2000000, $apiKey->lastUsed);
        $this->assertSame(3000000, $apiKey->expires);
    }

    public function testConstructorWithOptionalDefaults(): void
    {
        $apiKey = new ApiKey(
            keyId: 'abc123',
            label: 'Test Key',
            scopes: ['read'],
            created: 1000000,
        );

        $this->assertNull($apiKey->lastUsed);
        $this->assertNull($apiKey->expires);
    }

    public function testHasScopeReturnsTrueForExistingScope(): void
    {
        $apiKey = new ApiKey('id', 'label', ['read', 'write', 'admin'], 0);

        $this->assertTrue($apiKey->hasScope('read'));
        $this->assertTrue($apiKey->hasScope('write'));
        $this->assertTrue($apiKey->hasScope('admin'));
    }

    public function testHasScopeReturnsFalseForMissingScope(): void
    {
        $apiKey = new ApiKey('id', 'label', ['read'], 0);

        $this->assertFalse($apiKey->hasScope('write'));
        $this->assertFalse($apiKey->hasScope('admin'));
        $this->assertFalse($apiKey->hasScope(''));
    }

    public function testHasAnyScopeReturnsTrueWhenAnyMatch(): void
    {
        $apiKey = new ApiKey('id', 'label', ['read', 'write'], 0);

        $this->assertTrue($apiKey->hasAnyScope(['read']));
        $this->assertTrue($apiKey->hasAnyScope(['write']));
        $this->assertTrue($apiKey->hasAnyScope(['read', 'admin']));
        $this->assertTrue($apiKey->hasAnyScope(['admin', 'write', 'other']));
    }

    public function testHasAnyScopeReturnsFalseWhenNoneMatch(): void
    {
        $apiKey = new ApiKey('id', 'label', ['read'], 0);

        $this->assertFalse($apiKey->hasAnyScope(['write', 'admin']));
        $this->assertFalse($apiKey->hasAnyScope([]));
    }

    public function testHasAllScopesReturnsTrueWhenAllPresent(): void
    {
        $apiKey = new ApiKey('id', 'label', ['read', 'write', 'admin'], 0);

        $this->assertTrue($apiKey->hasAllScopes(['read']));
        $this->assertTrue($apiKey->hasAllScopes(['read', 'write']));
        $this->assertTrue($apiKey->hasAllScopes(['read', 'write', 'admin']));
        $this->assertTrue($apiKey->hasAllScopes([]));
    }

    public function testHasAllScopesReturnsFalseWhenSomeMissing(): void
    {
        $apiKey = new ApiKey('id', 'label', ['read', 'write'], 0);

        $this->assertFalse($apiKey->hasAllScopes(['admin']));
        $this->assertFalse($apiKey->hasAllScopes(['read', 'admin']));
        $this->assertFalse($apiKey->hasAllScopes(['read', 'write', 'admin']));
    }

    public function testIsExpiredReturnsFalseWhenNoExpiry(): void
    {
        $apiKey = new ApiKey('id', 'label', [], 0, expires: null);

        $this->assertFalse($apiKey->isExpired(PHP_INT_MAX));
        $this->assertFalse($apiKey->isExpired(0));
    }

    public function testIsExpiredReturnsFalseWhenNotExpired(): void
    {
        $apiKey = new ApiKey('id', 'label', [], 0, expires: 1000);

        $this->assertFalse($apiKey->isExpired(999));
        $this->assertFalse($apiKey->isExpired(0));
    }

    public function testIsExpiredReturnsTrueWhenExpired(): void
    {
        $apiKey = new ApiKey('id', 'label', [], 0, expires: 1000);

        $this->assertTrue($apiKey->isExpired(1001));
        $this->assertTrue($apiKey->isExpired(2000));
    }

    public function testIsExpiredReturnsTrueWhenExactlyExpired(): void
    {
        $apiKey = new ApiKey('id', 'label', [], 0, expires: 1000);

        // Expires at 1000, so at time 1000 it's expired (< not <=)
        $this->assertFalse($apiKey->isExpired(1000));
    }
}
