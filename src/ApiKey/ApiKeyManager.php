<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\ApiKey;

use CodeWheel\McpSecurity\ApiKey\Storage\StorageInterface;
use Psr\Clock\ClockInterface;

/**
 * Manages API keys with secure hashing and TTL support.
 */
final class ApiKeyManager implements ApiKeyManagerInterface
{
    private const DEFAULT_PREFIX = 'mcp';

    public function __construct(
        private readonly StorageInterface $storage,
        private readonly ClockInterface $clock,
        private readonly string $pepper = '',
        private readonly string $keyPrefix = self::DEFAULT_PREFIX,
    ) {}

    public function createKey(string $label, array $scopes, ?int $ttlSeconds = null): array
    {
        $label = trim($label);
        if ($label === '') {
            $label = 'Unnamed key';
        }

        $keyId = $this->generateKeyId();
        $secret = $this->generateSecret();
        $now = $this->clock->now()->getTimestamp();

        $expires = null;
        if ($ttlSeconds !== null && $ttlSeconds > 0) {
            $expires = $now + $ttlSeconds;
        }

        $record = [
            'label' => $label,
            'scopes' => array_values(array_unique(array_filter(array_map('strval', $scopes)))),
            'hash' => $this->hashSecret($secret),
            'created' => $now,
            'last_used' => null,
            'expires' => $expires,
        ];

        $this->storage->set($keyId, $record);

        return [
            'key_id' => $keyId,
            'api_key' => $this->keyPrefix . '.' . $keyId . '.' . $secret,
        ];
    }

    public function listKeys(): array
    {
        $all = $this->storage->getAll();
        $keys = [];

        foreach ($all as $keyId => $record) {
            if (!is_array($record)) {
                continue;
            }
            // Cast keyId to string in case PHP converted numeric-looking keys to int
            $keyId = (string) $keyId;
            $keys[$keyId] = $this->recordToApiKey($keyId, $record);
        }

        ksort($keys);
        return $keys;
    }

    public function getKey(string $keyId): ?ApiKey
    {
        $record = $this->storage->get($keyId);
        if (!is_array($record)) {
            return null;
        }
        return $this->recordToApiKey($keyId, $record);
    }

    public function revokeKey(string $keyId): bool
    {
        return $this->storage->delete($keyId);
    }

    public function validate(string $apiKey): ?ApiKey
    {
        $apiKey = trim($apiKey);
        if ($apiKey === '') {
            return null;
        }

        $parts = explode('.', $apiKey, 3);
        if (count($parts) !== 3) {
            return null;
        }

        [$prefix, $keyId, $secret] = $parts;
        if ($prefix !== $this->keyPrefix || $keyId === '' || $secret === '') {
            return null;
        }

        $record = $this->storage->get($keyId);
        if (!is_array($record) || empty($record['hash'])) {
            return null;
        }

        $now = $this->clock->now()->getTimestamp();
        $expires = $record['expires'] ?? null;
        if (is_numeric($expires) && $expires > 0 && $expires < $now) {
            return null;
        }

        $expected = (string) $record['hash'];
        $actual = $this->hashSecret($secret);

        if (!hash_equals($expected, $actual)) {
            return null;
        }

        // Update last-used timestamp
        $record['last_used'] = $now;
        $this->storage->set($keyId, $record);

        return $this->recordToApiKey($keyId, $record);
    }

    /**
     * @param array<string, mixed> $record
     */
    private function recordToApiKey(string $keyId, array $record): ApiKey
    {
        return new ApiKey(
            keyId: $keyId,
            label: (string) ($record['label'] ?? ''),
            scopes: array_values(array_filter($record['scopes'] ?? [])),
            created: (int) ($record['created'] ?? 0),
            lastUsed: isset($record['last_used']) ? (int) $record['last_used'] : null,
            expires: isset($record['expires']) ? (int) $record['expires'] : null,
        );
    }

    private function generateKeyId(): string
    {
        return substr(bin2hex(random_bytes(8)), 0, 12);
    }

    private function generateSecret(): string
    {
        $raw = random_bytes(32);
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    private function hashSecret(string $secret): string
    {
        return hash('sha256', $this->pepper . ':' . $secret);
    }
}
