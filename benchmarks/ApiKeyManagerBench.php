<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Benchmarks;

use CodeWheel\McpSecurity\ApiKey\ApiKeyManager;
use CodeWheel\McpSecurity\ApiKey\Storage\ArrayStorage;
use CodeWheel\McpSecurity\Clock\SystemClock;
use PhpBench\Attributes as Bench;

/**
 * Benchmarks for API key operations.
 */
#[Bench\Iterations(5)]
#[Bench\Revs(1000)]
#[Bench\Warmup(2)]
class ApiKeyManagerBench
{
    private ApiKeyManager $manager;
    private ArrayStorage $storage;
    private string $validApiKey;

    public function __construct()
    {
        $this->storage = new ArrayStorage();
        $this->manager = new ApiKeyManager(
            storage: $this->storage,
            clock: new SystemClock(),
            pepper: 'benchmark-pepper',
        );

        // Pre-create a key for validation benchmarks
        $result = $this->manager->createKey('Benchmark Key', ['read', 'write']);
        $this->validApiKey = $result['api_key'];
    }

    #[Bench\Subject]
    #[Bench\Groups(['create'])]
    public function benchCreateKey(): void
    {
        $this->manager->createKey('Test Key', ['read', 'write', 'admin']);
    }

    #[Bench\Subject]
    #[Bench\Groups(['validate'])]
    public function benchValidateKey(): void
    {
        $this->manager->validate($this->validApiKey);
    }

    #[Bench\Subject]
    #[Bench\Groups(['validate'])]
    public function benchValidateInvalidKey(): void
    {
        $this->manager->validate('mcp.invalid.key');
    }

    #[Bench\Subject]
    #[Bench\Groups(['list'])]
    public function benchListKeys(): void
    {
        $this->manager->listKeys();
    }

    #[Bench\Subject]
    #[Bench\Groups(['list'])]
    public function benchListKeysWithMany(): void
    {
        // Create 100 keys
        $storage = new ArrayStorage();
        $manager = new ApiKeyManager($storage, new SystemClock(), 'pepper');

        for ($i = 0; $i < 100; $i++) {
            $manager->createKey("Key $i", ['read']);
        }

        $manager->listKeys();
    }
}
