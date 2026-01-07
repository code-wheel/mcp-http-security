<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\ApiKey;

/**
 * Interface for API key management.
 */
interface ApiKeyManagerInterface
{
    /**
     * Create a new API key.
     *
     * @param string $label Human-readable label
     * @param string[] $scopes Allowed scopes for this key
     * @param int|null $ttlSeconds Time-to-live in seconds (null = no expiry)
     * @return array{key_id: string, api_key: string} Key ID and full API key (shown once)
     */
    public function createKey(string $label, array $scopes, ?int $ttlSeconds = null): array;

    /**
     * List all keys (without secrets).
     *
     * @return ApiKey[] Keys indexed by key ID
     */
    public function listKeys(): array;

    /**
     * Get a specific key by ID (without secret).
     */
    public function getKey(string $keyId): ?ApiKey;

    /**
     * Revoke (delete) a key by ID.
     *
     * @return bool True if key existed and was revoked
     */
    public function revokeKey(string $keyId): bool;

    /**
     * Validate an API key string.
     *
     * @return ApiKey|null Validated key or null if invalid
     */
    public function validate(string $apiKey): ?ApiKey;
}
