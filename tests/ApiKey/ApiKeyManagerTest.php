<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Tests\ApiKey;

use CodeWheel\McpSecurity\ApiKey\ApiKeyManager;
use CodeWheel\McpSecurity\ApiKey\Storage\ArrayStorage;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;

final class ApiKeyManagerTest extends TestCase
{
    private ApiKeyManager $manager;
    private ArrayStorage $storage;
    private MockClock $clock;

    protected function setUp(): void
    {
        $this->storage = new ArrayStorage();
        $this->clock = new MockClock();
        $this->manager = new ApiKeyManager(
            storage: $this->storage,
            clock: $this->clock,
            pepper: 'test-pepper',
        );
    }

    public function testCreateKeyReturnsKeyIdAndApiKey(): void
    {
        $result = $this->manager->createKey('Test Key', ['read', 'write']);

        $this->assertArrayHasKey('key_id', $result);
        $this->assertArrayHasKey('api_key', $result);
        $this->assertStringStartsWith('mcp.', $result['api_key']);
        $this->assertStringContainsString($result['key_id'], $result['api_key']);
    }

    public function testValidateReturnsApiKeyForValidToken(): void
    {
        $result = $this->manager->createKey('Test Key', ['read', 'write']);

        $apiKey = $this->manager->validate($result['api_key']);

        $this->assertNotNull($apiKey);
        $this->assertSame($result['key_id'], $apiKey->keyId);
        $this->assertSame('Test Key', $apiKey->label);
        $this->assertSame(['read', 'write'], $apiKey->scopes);
    }

    public function testValidateReturnsNullForInvalidToken(): void
    {
        $this->assertNull($this->manager->validate('invalid-token'));
        $this->assertNull($this->manager->validate('mcp.invalid.token'));
        $this->assertNull($this->manager->validate(''));
    }

    public function testValidateReturnsNullForExpiredKey(): void
    {
        $result = $this->manager->createKey('Expiring Key', ['read'], ttlSeconds: 3600);

        // Advance clock past expiry
        $this->clock->advance(7200);

        $this->assertNull($this->manager->validate($result['api_key']));
    }

    public function testListKeysReturnsAllKeys(): void
    {
        $this->manager->createKey('Key 1', ['read']);
        $this->manager->createKey('Key 2', ['write']);
        $this->manager->createKey('Key 3', ['admin']);

        $keys = $this->manager->listKeys();

        $this->assertCount(3, $keys);
        $labels = array_map(fn($k) => $k->label, $keys);
        $this->assertContains('Key 1', $labels);
        $this->assertContains('Key 2', $labels);
        $this->assertContains('Key 3', $labels);
    }

    public function testRevokeKeyRemovesKey(): void
    {
        $result = $this->manager->createKey('To Revoke', ['read']);

        $this->assertTrue($this->manager->revokeKey($result['key_id']));
        $this->assertNull($this->manager->validate($result['api_key']));
        $this->assertNull($this->manager->getKey($result['key_id']));
    }

    public function testRevokeKeyReturnsFalseForNonexistentKey(): void
    {
        $this->assertFalse($this->manager->revokeKey('nonexistent'));
    }

    public function testValidateUpdatesLastUsed(): void
    {
        $result = $this->manager->createKey('Test Key', ['read']);

        $keyBefore = $this->manager->getKey($result['key_id']);
        $this->assertNull($keyBefore->lastUsed);

        $this->manager->validate($result['api_key']);

        $keyAfter = $this->manager->getKey($result['key_id']);
        $this->assertNotNull($keyAfter->lastUsed);
    }

    public function testApiKeyHasScope(): void
    {
        $result = $this->manager->createKey('Test', ['read', 'write']);
        $apiKey = $this->manager->validate($result['api_key']);

        $this->assertTrue($apiKey->hasScope('read'));
        $this->assertTrue($apiKey->hasScope('write'));
        $this->assertFalse($apiKey->hasScope('admin'));
    }

    public function testApiKeyHasAnyScope(): void
    {
        $result = $this->manager->createKey('Test', ['read']);
        $apiKey = $this->manager->validate($result['api_key']);

        $this->assertTrue($apiKey->hasAnyScope(['read', 'write']));
        $this->assertFalse($apiKey->hasAnyScope(['admin']));
    }

    public function testApiKeyHasAllScopes(): void
    {
        $result = $this->manager->createKey('Test', ['read', 'write']);
        $apiKey = $this->manager->validate($result['api_key']);

        $this->assertTrue($apiKey->hasAllScopes(['read']));
        $this->assertTrue($apiKey->hasAllScopes(['read', 'write']));
        $this->assertFalse($apiKey->hasAllScopes(['read', 'admin']));
    }
}

/**
 * Mock clock for testing.
 */
final class MockClock implements ClockInterface
{
    private int $timestamp;

    public function __construct()
    {
        $this->timestamp = time();
    }

    public function now(): DateTimeImmutable
    {
        return (new DateTimeImmutable())->setTimestamp($this->timestamp);
    }

    public function advance(int $seconds): void
    {
        $this->timestamp += $seconds;
    }
}
