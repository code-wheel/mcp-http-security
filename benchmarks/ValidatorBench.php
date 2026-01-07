<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Benchmarks;

use CodeWheel\McpSecurity\Validation\IpValidator;
use CodeWheel\McpSecurity\Validation\OriginValidator;
use PhpBench\Attributes as Bench;

/**
 * Benchmarks for IP and Origin validation.
 */
#[Bench\Iterations(5)]
#[Bench\Revs(10000)]
#[Bench\Warmup(2)]
class ValidatorBench
{
    private IpValidator $ipValidatorSmall;
    private IpValidator $ipValidatorLarge;
    private OriginValidator $originValidatorSmall;
    private OriginValidator $originValidatorLarge;

    public function __construct()
    {
        // Small allowlist
        $this->ipValidatorSmall = new IpValidator([
            '127.0.0.1',
            '10.0.0.0/8',
            '::1',
        ]);

        // Large allowlist (100 entries)
        $largeIpList = ['127.0.0.1', '::1'];
        for ($i = 0; $i < 98; $i++) {
            $largeIpList[] = "192.168.{$i}.0/24";
        }
        $this->ipValidatorLarge = new IpValidator($largeIpList);

        // Small origin list
        $this->originValidatorSmall = new OriginValidator([
            'localhost',
            'example.com',
            '*.example.com',
        ]);

        // Large origin list
        $largeOriginList = [];
        for ($i = 0; $i < 100; $i++) {
            $largeOriginList[] = "site{$i}.example.com";
            $largeOriginList[] = "*.site{$i}.com";
        }
        $this->originValidatorLarge = new OriginValidator($largeOriginList);
    }

    // IP Validator Benchmarks

    #[Bench\Subject]
    #[Bench\Groups(['ip', 'small'])]
    public function benchIpValidatorSmallMatch(): void
    {
        $this->ipValidatorSmall->isAllowed('10.5.3.2');
    }

    #[Bench\Subject]
    #[Bench\Groups(['ip', 'small'])]
    public function benchIpValidatorSmallNoMatch(): void
    {
        $this->ipValidatorSmall->isAllowed('8.8.8.8');
    }

    #[Bench\Subject]
    #[Bench\Groups(['ip', 'large'])]
    public function benchIpValidatorLargeMatch(): void
    {
        $this->ipValidatorLarge->isAllowed('192.168.50.100');
    }

    #[Bench\Subject]
    #[Bench\Groups(['ip', 'large'])]
    public function benchIpValidatorLargeNoMatch(): void
    {
        $this->ipValidatorLarge->isAllowed('8.8.8.8');
    }

    #[Bench\Subject]
    #[Bench\Groups(['ip', 'ipv6'])]
    public function benchIpValidatorIpv6(): void
    {
        $this->ipValidatorSmall->isAllowed('::1');
    }

    // Origin Validator Benchmarks

    #[Bench\Subject]
    #[Bench\Groups(['origin', 'small'])]
    public function benchOriginValidatorSmallExact(): void
    {
        $this->originValidatorSmall->isAllowed('example.com');
    }

    #[Bench\Subject]
    #[Bench\Groups(['origin', 'small'])]
    public function benchOriginValidatorSmallWildcard(): void
    {
        $this->originValidatorSmall->isAllowed('api.example.com');
    }

    #[Bench\Subject]
    #[Bench\Groups(['origin', 'small'])]
    public function benchOriginValidatorSmallNoMatch(): void
    {
        $this->originValidatorSmall->isAllowed('evil.com');
    }

    #[Bench\Subject]
    #[Bench\Groups(['origin', 'large'])]
    public function benchOriginValidatorLargeMatch(): void
    {
        $this->originValidatorLarge->isAllowed('site50.example.com');
    }

    #[Bench\Subject]
    #[Bench\Groups(['origin', 'large'])]
    public function benchOriginValidatorLargeWildcard(): void
    {
        $this->originValidatorLarge->isAllowed('api.site50.com');
    }

    #[Bench\Subject]
    #[Bench\Groups(['origin', 'extract'])]
    public function benchExtractHostname(): void
    {
        $this->originValidatorSmall->extractHostname('https://api.example.com:8080/path?query=1');
    }
}
