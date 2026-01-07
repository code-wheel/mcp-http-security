<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Tests\ApiKey\Storage;

use CodeWheel\McpSecurity\ApiKey\Storage\ArrayStorage;
use PHPUnit\Framework\TestCase;

final class ArrayStorageTest extends TestCase
{
    public function testGetAllReturnsEmptyArrayByDefault(): void
    {
        $storage = new ArrayStorage();

        $this->assertSame([], $storage->getAll());
    }

    public function testGetAllReturnsInitialKeys(): void
    {
        $initial = [
            'key1' => ['label' => 'Key 1'],
            'key2' => ['label' => 'Key 2'],
        ];
        $storage = new ArrayStorage($initial);

        $this->assertSame($initial, $storage->getAll());
    }

    public function testSetAllReplacesAllKeys(): void
    {
        $storage = new ArrayStorage(['old' => ['label' => 'Old']]);

        $new = ['new' => ['label' => 'New']];
        $storage->setAll($new);

        $this->assertSame($new, $storage->getAll());
    }

    public function testGetReturnsNullForMissingKey(): void
    {
        $storage = new ArrayStorage();

        $this->assertNull($storage->get('nonexistent'));
    }

    public function testGetReturnsKeyData(): void
    {
        $storage = new ArrayStorage([
            'test' => ['label' => 'Test', 'scopes' => ['read']],
        ]);

        $this->assertSame(['label' => 'Test', 'scopes' => ['read']], $storage->get('test'));
    }

    public function testSetAddsNewKey(): void
    {
        $storage = new ArrayStorage();

        $storage->set('new', ['label' => 'New Key']);

        $this->assertSame(['label' => 'New Key'], $storage->get('new'));
    }

    public function testSetUpdatesExistingKey(): void
    {
        $storage = new ArrayStorage(['existing' => ['label' => 'Old']]);

        $storage->set('existing', ['label' => 'Updated']);

        $this->assertSame(['label' => 'Updated'], $storage->get('existing'));
    }

    public function testDeleteReturnsFalseForMissingKey(): void
    {
        $storage = new ArrayStorage();

        $this->assertFalse($storage->delete('nonexistent'));
    }

    public function testDeleteReturnsTrueAndRemovesKey(): void
    {
        $storage = new ArrayStorage(['test' => ['label' => 'Test']]);

        $this->assertTrue($storage->delete('test'));
        $this->assertNull($storage->get('test'));
    }

    public function testDeleteDoesNotAffectOtherKeys(): void
    {
        $storage = new ArrayStorage([
            'keep' => ['label' => 'Keep'],
            'delete' => ['label' => 'Delete'],
        ]);

        $storage->delete('delete');

        $this->assertSame(['label' => 'Keep'], $storage->get('keep'));
    }
}
