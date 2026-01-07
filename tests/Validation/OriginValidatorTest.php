<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Tests\Validation;

use CodeWheel\McpSecurity\Validation\OriginValidator;
use PHPUnit\Framework\TestCase;

final class OriginValidatorTest extends TestCase
{
    public function testEmptyAllowlistAllowsAll(): void
    {
        $validator = new OriginValidator([]);

        $this->assertTrue($validator->isAllowed('example.com'));
        $this->assertTrue($validator->isAllowed('evil.com'));
    }

    public function testExactHostnameMatch(): void
    {
        $validator = new OriginValidator(['example.com', 'localhost']);

        $this->assertTrue($validator->isAllowed('example.com'));
        $this->assertTrue($validator->isAllowed('localhost'));
        $this->assertFalse($validator->isAllowed('evil.com'));
    }

    public function testCaseInsensitive(): void
    {
        $validator = new OriginValidator(['Example.COM']);

        $this->assertTrue($validator->isAllowed('example.com'));
        $this->assertTrue($validator->isAllowed('EXAMPLE.COM'));
    }

    public function testWildcardSubdomain(): void
    {
        $validator = new OriginValidator(['*.example.com']);

        $this->assertTrue($validator->isAllowed('api.example.com'));
        $this->assertTrue($validator->isAllowed('foo.example.com'));
        $this->assertFalse($validator->isAllowed('example.com')); // Root not matched
        $this->assertFalse($validator->isAllowed('evil.com'));
    }

    public function testWildcardWithDeepSubdomain(): void
    {
        $validator = new OriginValidator(['*.example.com']);

        $this->assertTrue($validator->isAllowed('a.b.c.example.com'));
    }

    public function testExtractHostnameFromUrl(): void
    {
        $validator = new OriginValidator([]);

        $this->assertSame('example.com', $validator->extractHostname('https://example.com/path'));
        $this->assertSame('example.com', $validator->extractHostname('http://example.com:8080'));
        $this->assertSame('example.com', $validator->extractHostname('example.com'));
        $this->assertSame('localhost', $validator->extractHostname('http://localhost:3000'));
    }

    public function testExtractHostnameReturnsNullForEmpty(): void
    {
        $validator = new OriginValidator([]);

        $this->assertNull($validator->extractHostname(''));
        $this->assertNull($validator->extractHostname('   '));
    }

    public function testEmptyHostnameNotAllowed(): void
    {
        $validator = new OriginValidator(['example.com']);

        $this->assertFalse($validator->isAllowed(''));
    }
}
