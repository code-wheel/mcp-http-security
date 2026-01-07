<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Tests\ApiKey\Storage;

use CodeWheel\McpSecurity\ApiKey\Storage\PdoStorage;
use PDO;
use PHPUnit\Framework\TestCase;

final class PdoStorageTest extends TestCase
{
    private PDO $pdo;
    private PdoStorage $storage;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->storage = new PdoStorage($this->pdo, 'mcp_api_keys');
        $this->storage->ensureTable();
    }

    public function testEnsureTableCreatesTable(): void
    {
        // Table should already exist from setUp
        $stmt = $this->pdo->query("SELECT name FROM sqlite_master WHERE type='table' AND name='mcp_api_keys'");
        $result = $stmt->fetch();

        $this->assertNotFalse($result);
        $this->assertSame('mcp_api_keys', $result['name']);
    }

    public function testGetAllReturnsEmptyArrayWhenNoKeys(): void
    {
        $this->assertSame([], $this->storage->getAll());
    }

    public function testSetAllStoresAllKeys(): void
    {
        $data = [
            'key1' => ['label' => 'Key 1', 'scopes' => ['read']],
            'key2' => ['label' => 'Key 2', 'scopes' => ['write']],
        ];

        $this->storage->setAll($data);

        $this->assertSame($data, $this->storage->getAll());
    }

    public function testSetAllReplacesExistingKeys(): void
    {
        $this->storage->setAll(['old' => ['label' => 'Old']]);
        $this->storage->setAll(['new' => ['label' => 'New']]);

        $all = $this->storage->getAll();
        $this->assertCount(1, $all);
        $this->assertArrayHasKey('new', $all);
        $this->assertArrayNotHasKey('old', $all);
    }

    public function testGetReturnsNullForMissingKey(): void
    {
        $this->assertNull($this->storage->get('nonexistent'));
    }

    public function testGetReturnsKeyData(): void
    {
        $this->storage->setAll(['test' => ['label' => 'Test', 'scopes' => ['read']]]);

        $result = $this->storage->get('test');

        $this->assertSame(['label' => 'Test', 'scopes' => ['read']], $result);
    }

    public function testSetAddsNewKey(): void
    {
        $this->storage->set('new', ['label' => 'New Key']);

        $this->assertSame(['label' => 'New Key'], $this->storage->get('new'));
    }

    public function testSetUpdatesExistingKey(): void
    {
        $this->storage->set('key', ['label' => 'Original']);
        $this->storage->set('key', ['label' => 'Updated']);

        $this->assertSame(['label' => 'Updated'], $this->storage->get('key'));
    }

    public function testDeleteReturnsFalseForMissingKey(): void
    {
        $this->assertFalse($this->storage->delete('nonexistent'));
    }

    public function testDeleteReturnsTrueAndRemovesKey(): void
    {
        $this->storage->set('test', ['label' => 'Test']);

        $this->assertTrue($this->storage->delete('test'));
        $this->assertNull($this->storage->get('test'));
    }

    public function testDeleteDoesNotAffectOtherKeys(): void
    {
        $this->storage->set('keep', ['label' => 'Keep']);
        $this->storage->set('delete', ['label' => 'Delete']);

        $this->storage->delete('delete');

        $this->assertSame(['label' => 'Keep'], $this->storage->get('keep'));
    }

    public function testCustomTableName(): void
    {
        $storage = new PdoStorage($this->pdo, 'custom_keys');
        $storage->ensureTable();

        $storage->set('test', ['label' => 'Test']);

        $this->assertSame(['label' => 'Test'], $storage->get('test'));

        // Verify it's in the custom table
        $stmt = $this->pdo->query("SELECT name FROM sqlite_master WHERE type='table' AND name='custom_keys'");
        $this->assertNotFalse($stmt->fetch());
    }

    public function testComplexDataStructures(): void
    {
        $data = [
            'key' => [
                'label' => 'Complex',
                'scopes' => ['read', 'write', 'admin'],
                'created' => 1234567890,
                'expires' => 9999999999,
                'metadata' => [
                    'nested' => ['value' => true],
                ],
            ],
        ];

        $this->storage->setAll($data);

        $this->assertSame($data, $this->storage->getAll());
    }
}
