<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\ApiKey\Storage;

use PDO;
use RuntimeException;

/**
 * PDO-based storage for database deployments.
 *
 * Expected table schema:
 * CREATE TABLE mcp_api_keys (
 *     key_id VARCHAR(32) PRIMARY KEY,
 *     data JSON NOT NULL
 * );
 */
final class PdoStorage implements StorageInterface
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly string $tableName = 'mcp_api_keys',
    ) {}

    public function getAll(): array
    {
        $stmt = $this->pdo->prepare(
            "SELECT key_id, data FROM {$this->tableName}"
        );
        $stmt->execute();

        $keys = [];
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            if (!is_array($row)) {
                continue;
            }
            $keyId = $row['key_id'] ?? null;
            $rawData = $row['data'] ?? null;
            if (!is_string($keyId) || !is_string($rawData)) {
                continue;
            }
            $data = json_decode($rawData, true);
            if (is_array($data)) {
                $keys[$keyId] = $data;
            }
        }

        return $keys;
    }

    public function setAll(array $keys): void
    {
        $this->pdo->beginTransaction();
        try {
            $this->pdo->exec("DELETE FROM {$this->tableName}");

            $stmt = $this->pdo->prepare(
                "INSERT INTO {$this->tableName} (key_id, data) VALUES (:key_id, :data)"
            );

            foreach ($keys as $keyId => $data) {
                $stmt->execute([
                    'key_id' => $keyId,
                    'data' => json_encode($data, JSON_THROW_ON_ERROR),
                ]);
            }

            $this->pdo->commit();
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            throw new RuntimeException("Failed to store keys: " . $e->getMessage(), 0, $e);
        }
    }

    public function get(string $keyId): ?array
    {
        $stmt = $this->pdo->prepare(
            "SELECT data FROM {$this->tableName} WHERE key_id = :key_id"
        );
        $stmt->execute(['key_id' => $keyId]);

        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            return null;
        }

        $rawData = $row['data'] ?? null;
        if (!is_string($rawData)) {
            return null;
        }

        $data = json_decode($rawData, true);
        return is_array($data) ? $data : null;
    }

    public function set(string $keyId, array $data): void
    {
        $json = json_encode($data, JSON_THROW_ON_ERROR);

        // Use UPSERT pattern (works across MySQL, PostgreSQL, SQLite)
        $stmt = $this->pdo->prepare(
            "INSERT INTO {$this->tableName} (key_id, data) VALUES (:key_id, :data)
             ON CONFLICT(key_id) DO UPDATE SET data = :data2"
        );

        try {
            $stmt->execute([
                'key_id' => $keyId,
                'data' => $json,
                'data2' => $json,
            ]);
        } catch (\PDOException $e) {
            // Fallback for MySQL which uses different syntax
            if (str_contains($e->getMessage(), 'CONFLICT')) {
                $stmt = $this->pdo->prepare(
                    "INSERT INTO {$this->tableName} (key_id, data) VALUES (:key_id, :data)
                     ON DUPLICATE KEY UPDATE data = :data2"
                );
                $stmt->execute([
                    'key_id' => $keyId,
                    'data' => $json,
                    'data2' => $json,
                ]);
            } else {
                throw $e;
            }
        }
    }

    public function delete(string $keyId): bool
    {
        $stmt = $this->pdo->prepare(
            "DELETE FROM {$this->tableName} WHERE key_id = :key_id"
        );
        $stmt->execute(['key_id' => $keyId]);

        return $stmt->rowCount() > 0;
    }

    /**
     * Create the table if it doesn't exist.
     */
    public function ensureTable(): void
    {
        $driver = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);

        $sql = match ($driver) {
            'mysql' => "CREATE TABLE IF NOT EXISTS {$this->tableName} (
                key_id VARCHAR(32) PRIMARY KEY,
                data JSON NOT NULL
            )",
            'pgsql' => "CREATE TABLE IF NOT EXISTS {$this->tableName} (
                key_id VARCHAR(32) PRIMARY KEY,
                data JSONB NOT NULL
            )",
            default => "CREATE TABLE IF NOT EXISTS {$this->tableName} (
                key_id VARCHAR(32) PRIMARY KEY,
                data TEXT NOT NULL
            )",
        };

        $this->pdo->exec($sql);
    }
}
