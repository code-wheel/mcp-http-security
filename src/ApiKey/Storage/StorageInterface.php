<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\ApiKey\Storage;

/**
 * Interface for API key storage backends.
 */
interface StorageInterface
{
    /**
     * Get all stored keys.
     *
     * @return array<string, array<string, mixed>> Keys indexed by key ID
     */
    public function getAll(): array;

    /**
     * Store all keys (replaces existing data).
     *
     * @param array<string, array<string, mixed>> $keys
     */
    public function setAll(array $keys): void;

    /**
     * Get a single key by ID.
     *
     * @return array<string, mixed>|null Key data or null if not found
     */
    public function get(string $keyId): ?array;

    /**
     * Store a single key.
     *
     * @param array<string, mixed> $data
     */
    public function set(string $keyId, array $data): void;

    /**
     * Delete a key by ID.
     *
     * @return bool True if key existed and was deleted
     */
    public function delete(string $keyId): bool;
}
