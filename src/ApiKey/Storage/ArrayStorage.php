<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\ApiKey\Storage;

/**
 * In-memory storage for testing and ephemeral use cases.
 */
final class ArrayStorage implements StorageInterface
{
    /**
     * @param array<string, array<string, mixed>> $keys Initial keys
     */
    public function __construct(
        private array $keys = [],
    ) {}

    public function getAll(): array
    {
        return $this->keys;
    }

    public function setAll(array $keys): void
    {
        $this->keys = $keys;
    }

    public function get(string $keyId): ?array
    {
        return $this->keys[$keyId] ?? null;
    }

    public function set(string $keyId, array $data): void
    {
        $this->keys[$keyId] = $data;
    }

    public function delete(string $keyId): bool
    {
        if (!isset($this->keys[$keyId])) {
            return false;
        }
        unset($this->keys[$keyId]);
        return true;
    }
}
