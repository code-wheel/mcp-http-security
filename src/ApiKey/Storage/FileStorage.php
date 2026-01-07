<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\ApiKey\Storage;

use RuntimeException;

/**
 * JSON file-based storage for simple deployments.
 */
final class FileStorage implements StorageInterface
{
    public function __construct(
        private readonly string $filePath,
    ) {}

    public function getAll(): array
    {
        if (!file_exists($this->filePath)) {
            return [];
        }

        $content = file_get_contents($this->filePath);
        if ($content === false) {
            throw new RuntimeException("Failed to read file: {$this->filePath}");
        }

        $data = json_decode($content, true);
        if (!is_array($data)) {
            return [];
        }

        return $data;
    }

    public function setAll(array $keys): void
    {
        $this->ensureDirectory();

        $json = json_encode($keys, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
        $result = file_put_contents($this->filePath, $json, LOCK_EX);

        if ($result === false) {
            throw new RuntimeException("Failed to write file: {$this->filePath}");
        }
    }

    public function get(string $keyId): ?array
    {
        $all = $this->getAll();
        return $all[$keyId] ?? null;
    }

    public function set(string $keyId, array $data): void
    {
        $all = $this->getAll();
        $all[$keyId] = $data;
        $this->setAll($all);
    }

    public function delete(string $keyId): bool
    {
        $all = $this->getAll();
        if (!isset($all[$keyId])) {
            return false;
        }
        unset($all[$keyId]);
        $this->setAll($all);
        return true;
    }

    private function ensureDirectory(): void
    {
        $dir = dirname($this->filePath);
        if (!is_dir($dir)) {
            if (!mkdir($dir, 0755, true) && !is_dir($dir)) {
                throw new RuntimeException("Failed to create directory: {$dir}");
            }
        }
    }
}
