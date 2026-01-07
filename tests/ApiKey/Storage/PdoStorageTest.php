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

    public function testSetAllRollsBackOnError(): void
    {
        // Store initial data
        $this->storage->set('existing', ['label' => 'Existing']);

        // Create a mock PDO that will fail during insert
        $mockPdo = $this->createMock(PDO::class);
        $mockPdo->method('getAttribute')->willReturn('sqlite');
        $mockPdo->method('beginTransaction')->willReturn(true);
        $mockPdo->method('exec')->willReturn(0);
        $mockPdo->method('prepare')->willThrowException(new \PDOException('Simulated failure'));
        $mockPdo->expects($this->once())->method('rollBack');

        $storage = new PdoStorage($mockPdo, 'test_keys');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Failed to store keys');
        $storage->setAll(['new' => ['label' => 'New']]);
    }

    public function testGetReturnsNullForInvalidJson(): void
    {
        // Manually insert invalid JSON data
        $stmt = $this->pdo->prepare(
            "INSERT INTO mcp_api_keys (key_id, data) VALUES (:key_id, :data)"
        );
        $stmt->execute(['key_id' => 'invalid', 'data' => 'not valid json']);

        $result = $this->storage->get('invalid');
        $this->assertNull($result);
    }

    public function testGetAllSkipsInvalidJsonRows(): void
    {
        // Insert one valid and one invalid row
        $stmt = $this->pdo->prepare(
            "INSERT INTO mcp_api_keys (key_id, data) VALUES (:key_id, :data)"
        );
        $stmt->execute(['key_id' => 'valid', 'data' => '{"label": "Valid"}']);
        $stmt->execute(['key_id' => 'invalid', 'data' => 'not json']);

        $all = $this->storage->getAll();

        $this->assertCount(1, $all);
        $this->assertArrayHasKey('valid', $all);
        $this->assertArrayNotHasKey('invalid', $all);
    }

    public function testEnsureTableForMysql(): void
    {
        $mockPdo = $this->createMock(PDO::class);
        $mockPdo->method('getAttribute')
            ->with(PDO::ATTR_DRIVER_NAME)
            ->willReturn('mysql');
        $mockPdo->expects($this->once())
            ->method('exec')
            ->with($this->stringContains('JSON NOT NULL'));

        $storage = new PdoStorage($mockPdo, 'mysql_keys');
        $storage->ensureTable();
    }

    public function testEnsureTableForPostgres(): void
    {
        $mockPdo = $this->createMock(PDO::class);
        $mockPdo->method('getAttribute')
            ->with(PDO::ATTR_DRIVER_NAME)
            ->willReturn('pgsql');
        $mockPdo->expects($this->once())
            ->method('exec')
            ->with($this->stringContains('JSONB NOT NULL'));

        $storage = new PdoStorage($mockPdo, 'pgsql_keys');
        $storage->ensureTable();
    }

    public function testSetWithMysqlFallback(): void
    {
        // Create a mock that simulates the SQLite CONFLICT error on first try
        $callCount = 0;
        $mockStmt = $this->createMock(\PDOStatement::class);
        $mockStmt->method('execute')
            ->willReturnCallback(function () use (&$callCount) {
                $callCount++;
                if ($callCount === 1) {
                    throw new \PDOException('SQLSTATE: CONFLICT error');
                }
                return true;
            });

        $mockPdo = $this->createMock(PDO::class);
        $mockPdo->method('getAttribute')->willReturn('mysql');
        $mockPdo->method('prepare')->willReturn($mockStmt);

        $storage = new PdoStorage($mockPdo, 'mysql_keys');
        $storage->set('key1', ['label' => 'Test']);

        // Should have called execute twice (first failed, second succeeded)
        $this->assertSame(2, $callCount);
    }

    public function testSetRethrowsNonConflictException(): void
    {
        $mockStmt = $this->createMock(\PDOStatement::class);
        $mockStmt->method('execute')
            ->willThrowException(new \PDOException('Connection lost'));

        $mockPdo = $this->createMock(PDO::class);
        $mockPdo->method('getAttribute')->willReturn('sqlite');
        $mockPdo->method('prepare')->willReturn($mockStmt);

        $storage = new PdoStorage($mockPdo, 'test_keys');

        $this->expectException(\PDOException::class);
        $this->expectExceptionMessage('Connection lost');
        $storage->set('key1', ['label' => 'Test']);
    }
}
