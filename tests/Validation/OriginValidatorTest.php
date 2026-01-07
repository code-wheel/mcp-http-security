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

    public function testEmptyPatternInAllowlist(): void
    {
        // Empty/whitespace patterns should be skipped
        $validator = new OriginValidator(['', '   ', 'example.com']);

        $this->assertTrue($validator->isAllowed('example.com'));
        $this->assertFalse($validator->isAllowed('other.com'));
    }

    public function testWhitespaceOnlyHostnameNotAllowed(): void
    {
        $validator = new OriginValidator(['example.com']);

        $this->assertFalse($validator->isAllowed('   '));
    }

    public function testExtractHostnameFromInvalidUrl(): void
    {
        $validator = new OriginValidator([]);

        // URL with scheme but no host
        $this->assertNull($validator->extractHostname('file:///path/to/file'));
        // Just a scheme with empty host
        $this->assertNull($validator->extractHostname('http://'));
    }

    public function testTrimsWhitespaceInAllowlist(): void
    {
        $validator = new OriginValidator(['  example.com  ', '  *.test.com  ']);

        $this->assertTrue($validator->isAllowed('example.com'));
        $this->assertTrue($validator->isAllowed('api.test.com'));
    }

    public function testWildcardDoesNotMatchRoot(): void
    {
        $validator = new OriginValidator(['*.']);

        // Wildcard with just a dot shouldn't match anything meaningful
        $this->assertFalse($validator->isAllowed('example.com'));
    }

    public function testWildcardWithEmptySuffix(): void
    {
        // Pattern '*.' after removing '*' gives just '.'
        $validator = new OriginValidator(['*.']);

        $this->assertFalse($validator->isAllowed('example'));
        $this->assertFalse($validator->isAllowed('example.com'));
    }

    public function testExtractHostnameLowercases(): void
    {
        $validator = new OriginValidator([]);

        $this->assertSame('example.com', $validator->extractHostname('HTTPS://EXAMPLE.COM/path'));
        $this->assertSame('example.com', $validator->extractHostname('EXAMPLE.COM'));
    }
}
