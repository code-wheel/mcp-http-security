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

    public function testCreateKeyWithEmptyLabelUsesDefault(): void
    {
        $result = $this->manager->createKey('', ['read']);
        $apiKey = $this->manager->getKey($result['key_id']);

        $this->assertSame('Unnamed key', $apiKey->label);
    }

    public function testCreateKeyWithWhitespaceOnlyLabelUsesDefault(): void
    {
        $result = $this->manager->createKey('   ', ['read']);
        $apiKey = $this->manager->getKey($result['key_id']);

        $this->assertSame('Unnamed key', $apiKey->label);
    }

    public function testValidateReturnsNullForWrongPrefix(): void
    {
        $result = $this->manager->createKey('Test', ['read']);
        $apiKey = $result['api_key'];

        // Change prefix from 'mcp' to 'wrong'
        $wrongPrefix = str_replace('mcp.', 'wrong.', $apiKey);

        $this->assertNull($this->manager->validate($wrongPrefix));
    }

    public function testValidateReturnsNullForEmptyKeyId(): void
    {
        $this->assertNull($this->manager->validate('mcp..secret'));
    }

    public function testValidateReturnsNullForEmptySecret(): void
    {
        $this->assertNull($this->manager->validate('mcp.keyid.'));
    }

    public function testValidateReturnsNullForWrongSecret(): void
    {
        $result = $this->manager->createKey('Test', ['read']);
        $keyId = $result['key_id'];

        // Use correct prefix and keyId but wrong secret
        $wrongSecret = "mcp.{$keyId}.wrongsecret";

        $this->assertNull($this->manager->validate($wrongSecret));
    }

    public function testValidateReturnsNullForMissingHash(): void
    {
        // Manually add a record without hash
        $this->storage->set('nohash', [
            'label' => 'No Hash',
            'scopes' => ['read'],
            'created' => time(),
        ]);

        $this->assertNull($this->manager->validate('mcp.nohash.anysecret'));
    }

    public function testListKeysSortsById(): void
    {
        // Create keys - they will have random IDs
        $this->manager->createKey('Key A', ['read']);
        $this->manager->createKey('Key B', ['write']);
        $this->manager->createKey('Key C', ['admin']);

        $keys = $this->manager->listKeys();

        // Verify keys are sorted by ID
        $keyIds = array_keys($keys);
        $sortedKeyIds = $keyIds;
        sort($sortedKeyIds);

        $this->assertSame($sortedKeyIds, $keyIds);
    }

    public function testGetKeyReturnsNullForNonexistentKey(): void
    {
        $this->assertNull($this->manager->getKey('nonexistent'));
    }

    public function testCreateKeyDeduplicatesScopes(): void
    {
        $result = $this->manager->createKey('Test', ['read', 'write', 'read', 'admin', 'write']);
        $apiKey = $this->manager->getKey($result['key_id']);

        $this->assertCount(3, $apiKey->scopes);
        $this->assertTrue($apiKey->hasScope('read'));
        $this->assertTrue($apiKey->hasScope('write'));
        $this->assertTrue($apiKey->hasScope('admin'));
    }

    public function testCustomPrefixIsUsed(): void
    {
        $manager = new ApiKeyManager(
            storage: $this->storage,
            clock: $this->clock,
            pepper: 'test',
            keyPrefix: 'custom',
        );

        $result = $manager->createKey('Test', ['read']);

        $this->assertStringStartsWith('custom.', $result['api_key']);

        // Should validate with the custom prefix
        $apiKey = $manager->validate($result['api_key']);
        $this->assertNotNull($apiKey);
    }

    public function testValidateTrimsWhitespace(): void
    {
        $result = $this->manager->createKey('Test', ['read']);

        // Add whitespace around the key
        $apiKey = $this->manager->validate("  {$result['api_key']}  ");

        $this->assertNotNull($apiKey);
    }

    public function testListKeysSkipsNonArrayRecords(): void
    {
        // Use a custom storage that can return mixed types
        $storage = new CorruptibleStorage();
        $manager = new ApiKeyManager($storage, $this->clock, 'pepper');

        // Create a valid key first
        $result = $manager->createKey('Valid', ['read']);

        // Corrupt the storage with a non-array value
        $storage->corruptKey('bad_key', 'not an array');

        $keys = $manager->listKeys();

        // Should only return the valid key, skipping corrupted one
        $this->assertCount(1, $keys);
        $this->assertArrayHasKey($result['key_id'], $keys);
    }
}

/**
 * Storage that allows corrupting data for testing edge cases.
 */
final class CorruptibleStorage implements \CodeWheel\McpSecurity\ApiKey\Storage\StorageInterface
{
    /** @var array<string, mixed> */
    private array $data = [];

    public function getAll(): array
    {
        return $this->data;
    }

    public function setAll(array $keys): void
    {
        $this->data = $keys;
    }

    public function get(string $keyId): ?array
    {
        $value = $this->data[$keyId] ?? null;
        return is_array($value) ? $value : null;
    }

    public function set(string $keyId, array $data): void
    {
        $this->data[$keyId] = $data;
    }

    public function delete(string $keyId): bool
    {
        if (!isset($this->data[$keyId])) {
            return false;
        }
        unset($this->data[$keyId]);
        return true;
    }

    /**
     * Corrupt a key with a non-array value for testing.
     */
    public function corruptKey(string $keyId, mixed $value): void
    {
        $this->data[$keyId] = $value;
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
