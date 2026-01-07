<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Tests\ApiKey\Storage;

use CodeWheel\McpSecurity\ApiKey\Storage\FileStorage;
use PHPUnit\Framework\TestCase;

final class FileStorageTest extends TestCase
{
    private string $tempDir;
    private string $filePath;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/mcp-security-test-' . uniqid();
        mkdir($this->tempDir, 0755, true);
        $this->filePath = $this->tempDir . '/api-keys.json';
    }

    protected function tearDown(): void
    {
        if (file_exists($this->filePath)) {
            unlink($this->filePath);
        }
        if (is_dir($this->tempDir)) {
            rmdir($this->tempDir);
        }
    }

    public function testGetAllReturnsEmptyArrayWhenFileNotExists(): void
    {
        $storage = new FileStorage($this->filePath);

        $this->assertSame([], $storage->getAll());
    }

    public function testGetAllReturnsEmptyArrayForInvalidJson(): void
    {
        file_put_contents($this->filePath, 'not json');
        $storage = new FileStorage($this->filePath);

        $this->assertSame([], $storage->getAll());
    }

    public function testGetAllReturnsEmptyArrayForNonArrayJson(): void
    {
        file_put_contents($this->filePath, '"string"');
        $storage = new FileStorage($this->filePath);

        $this->assertSame([], $storage->getAll());
    }

    public function testSetAllWritesJsonFile(): void
    {
        $storage = new FileStorage($this->filePath);
        $data = ['key1' => ['label' => 'Test']];

        $storage->setAll($data);

        $this->assertFileExists($this->filePath);
        $content = file_get_contents($this->filePath);
        $this->assertJson($content);
        $this->assertSame($data, json_decode($content, true));
    }

    public function testSetAllCreatesDirectory(): void
    {
        $nestedPath = $this->tempDir . '/nested/dir/keys.json';
        $storage = new FileStorage($nestedPath);

        $storage->setAll(['key' => ['label' => 'Test']]);

        $this->assertFileExists($nestedPath);

        // Cleanup
        unlink($nestedPath);
        rmdir(dirname($nestedPath));
        rmdir(dirname(dirname($nestedPath)));
    }

    public function testGetReturnsNullForMissingKey(): void
    {
        $storage = new FileStorage($this->filePath);
        $storage->setAll(['other' => ['label' => 'Other']]);

        $this->assertNull($storage->get('nonexistent'));
    }

    public function testGetReturnsKeyData(): void
    {
        $storage = new FileStorage($this->filePath);
        $storage->setAll(['test' => ['label' => 'Test', 'scopes' => ['read']]]);

        $result = $storage->get('test');

        $this->assertSame(['label' => 'Test', 'scopes' => ['read']], $result);
    }

    public function testSetAddsNewKey(): void
    {
        $storage = new FileStorage($this->filePath);
        $storage->setAll(['existing' => ['label' => 'Existing']]);

        $storage->set('new', ['label' => 'New']);

        $this->assertSame(['label' => 'New'], $storage->get('new'));
        $this->assertSame(['label' => 'Existing'], $storage->get('existing'));
    }

    public function testSetUpdatesExistingKey(): void
    {
        $storage = new FileStorage($this->filePath);
        $storage->setAll(['key' => ['label' => 'Old']]);

        $storage->set('key', ['label' => 'Updated']);

        $this->assertSame(['label' => 'Updated'], $storage->get('key'));
    }

    public function testDeleteReturnsFalseForMissingKey(): void
    {
        $storage = new FileStorage($this->filePath);

        $this->assertFalse($storage->delete('nonexistent'));
    }

    public function testDeleteReturnsTrueAndRemovesKey(): void
    {
        $storage = new FileStorage($this->filePath);
        $storage->setAll(['test' => ['label' => 'Test']]);

        $this->assertTrue($storage->delete('test'));
        $this->assertNull($storage->get('test'));
    }

    public function testRoundTripPreservesData(): void
    {
        $storage = new FileStorage($this->filePath);
        $data = [
            'key1' => ['label' => 'Key 1', 'scopes' => ['read', 'write'], 'created' => 1234567890],
            'key2' => ['label' => 'Key 2', 'scopes' => ['admin'], 'expires' => 9999999999],
        ];

        $storage->setAll($data);

        // Create new instance to read from disk
        $storage2 = new FileStorage($this->filePath);
        $this->assertSame($data, $storage2->getAll());
    }
}
