<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Tests\Validation;

use CodeWheel\McpSecurity\Exception\ValidationException;
use CodeWheel\McpSecurity\Validation\IpValidator;
use CodeWheel\McpSecurity\Validation\OriginValidator;
use CodeWheel\McpSecurity\Validation\RequestValidator;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;

final class RequestValidatorTest extends TestCase
{
    public function testValidatePassesWhenIpAndOriginAllowed(): void
    {
        $validator = new RequestValidator(
            allowedIps: ['127.0.0.1'],
            allowedOrigins: ['localhost'],
        );

        $request = $this->createRequest(
            serverParams: ['REMOTE_ADDR' => '127.0.0.1'],
            headers: ['Host' => 'localhost'],
        );

        // Should not throw
        $validator->validate($request);
        $this->assertTrue(true);
    }

    public function testValidateThrowsWhenIpNotAllowed(): void
    {
        $validator = new RequestValidator(
            allowedIps: ['127.0.0.1'],
            allowedOrigins: [],
        );

        $request = $this->createRequest(
            serverParams: ['REMOTE_ADDR' => '192.168.1.1'],
        );

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('IP not allowed');
        $validator->validate($request);
    }

    public function testValidateThrowsWhenOriginNotAllowed(): void
    {
        $validator = new RequestValidator(
            allowedIps: [],
            allowedOrigins: ['trusted.com'],
        );

        $request = $this->createRequest(
            headers: ['Origin' => 'https://evil.com'],
        );

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Origin not allowed');
        $validator->validate($request);
    }

    public function testValidatePassesWhenNoIpInRequest(): void
    {
        $validator = new RequestValidator(
            allowedIps: ['127.0.0.1'],
            allowedOrigins: [],
        );

        $request = $this->createRequest(serverParams: []);

        // Should not throw - no IP means we can't validate
        $validator->validate($request);
        $this->assertTrue(true);
    }

    public function testValidatePassesWhenNoOriginInRequest(): void
    {
        $validator = new RequestValidator(
            allowedIps: [],
            allowedOrigins: ['trusted.com'],
        );

        $request = $this->createRequest(headers: []);

        // Should not throw - no origin means we can't validate
        $validator->validate($request);
        $this->assertTrue(true);
    }

    public function testValidateUsesXForwardedForHeader(): void
    {
        $validator = new RequestValidator(
            allowedIps: ['10.0.0.1'],
            allowedOrigins: [],
        );

        $request = $this->createRequest(
            serverParams: ['REMOTE_ADDR' => '192.168.1.1'],
            headers: ['X-Forwarded-For' => '10.0.0.1, 192.168.1.1'],
        );

        // Should pass - uses first IP from X-Forwarded-For
        $validator->validate($request);
        $this->assertTrue(true);
    }

    public function testValidateUsesOriginHeader(): void
    {
        $validator = new RequestValidator(
            allowedIps: [],
            allowedOrigins: ['trusted.com'],
        );

        $request = $this->createRequest(
            headers: ['Origin' => 'https://trusted.com'],
        );

        $validator->validate($request);
        $this->assertTrue(true);
    }

    public function testValidateUsesRefererHeader(): void
    {
        $validator = new RequestValidator(
            allowedIps: [],
            allowedOrigins: ['trusted.com'],
        );

        $request = $this->createRequest(
            headers: ['Referer' => 'https://trusted.com/page'],
        );

        $validator->validate($request);
        $this->assertTrue(true);
    }

    public function testValidateUsesHostHeader(): void
    {
        $validator = new RequestValidator(
            allowedIps: [],
            allowedOrigins: ['trusted.com'],
        );

        $request = $this->createRequest(
            headers: ['Host' => 'trusted.com:8080'],
        );

        $validator->validate($request);
        $this->assertTrue(true);
    }

    public function testIsValidReturnsTrueWhenValid(): void
    {
        $validator = new RequestValidator(
            allowedIps: ['127.0.0.1'],
            allowedOrigins: ['localhost'],
        );

        $request = $this->createRequest(
            serverParams: ['REMOTE_ADDR' => '127.0.0.1'],
            headers: ['Host' => 'localhost'],
        );

        $this->assertTrue($validator->isValid($request));
    }

    public function testIsValidReturnsFalseWhenInvalid(): void
    {
        $validator = new RequestValidator(
            allowedIps: ['127.0.0.1'],
            allowedOrigins: [],
        );

        $request = $this->createRequest(
            serverParams: ['REMOTE_ADDR' => '192.168.1.1'],
        );

        $this->assertFalse($validator->isValid($request));
    }

    public function testCustomValidatorsCanBeInjected(): void
    {
        // Use real validators with specific allowlists instead of mocks
        // since IpValidator and OriginValidator are final classes
        $ipValidator = new IpValidator(['192.168.0.0/16']);
        $originValidator = new OriginValidator(['example.com', '*.example.com']);

        $validator = new RequestValidator(
            allowedIps: [],
            allowedOrigins: [],
            ipValidator: $ipValidator,
            originValidator: $originValidator,
        );

        $request = $this->createRequest(
            serverParams: ['REMOTE_ADDR' => '192.168.1.1'],
            headers: ['Origin' => 'https://api.example.com'],
        );

        $this->assertTrue($validator->isValid($request));
    }

    public function testValidateIgnoresEmptyXForwardedFor(): void
    {
        $validator = new RequestValidator(
            allowedIps: ['192.168.1.1'],
            allowedOrigins: [],
        );

        // Empty X-Forwarded-For should fall back to REMOTE_ADDR
        $request = $this->createRequest(
            serverParams: ['REMOTE_ADDR' => '192.168.1.1'],
            headers: ['X-Forwarded-For' => ''],
        );

        $validator->validate($request);
        $this->assertTrue(true);
    }

    public function testValidateIgnoresWhitespaceOnlyXForwardedFor(): void
    {
        $validator = new RequestValidator(
            allowedIps: ['192.168.1.1'],
            allowedOrigins: [],
        );

        // Whitespace-only X-Forwarded-For should fall back to REMOTE_ADDR
        $request = $this->createRequest(
            serverParams: ['REMOTE_ADDR' => '192.168.1.1'],
            headers: ['X-Forwarded-For' => '   ,   '],
        );

        $validator->validate($request);
        $this->assertTrue(true);
    }

    public function testValidateHandlesNonStringRemoteAddr(): void
    {
        $validator = new RequestValidator(
            allowedIps: ['127.0.0.1'],
            allowedOrigins: [],
        );

        // Non-string REMOTE_ADDR should result in null IP
        $request = $this->createRequest(
            serverParams: ['REMOTE_ADDR' => ['127.0.0.1']],
        );

        // Should pass - no valid IP means we can't validate
        $validator->validate($request);
        $this->assertTrue(true);
    }

    public function testValidateHandlesEmptyRemoteAddr(): void
    {
        $validator = new RequestValidator(
            allowedIps: ['127.0.0.1'],
            allowedOrigins: [],
        );

        // Empty string REMOTE_ADDR should result in null IP
        $request = $this->createRequest(
            serverParams: ['REMOTE_ADDR' => ''],
        );

        // Should pass - no valid IP means we can't validate
        $validator->validate($request);
        $this->assertTrue(true);
    }

    public function testValidateWithHostHeaderWithoutPort(): void
    {
        $validator = new RequestValidator(
            allowedIps: [],
            allowedOrigins: ['example.com'],
        );

        $request = $this->createRequest(
            headers: ['Host' => 'example.com'],
        );

        $validator->validate($request);
        $this->assertTrue(true);
    }

    /**
     * @param array<string, mixed> $serverParams
     * @param array<string, string> $headers
     */
    private function createRequest(array $serverParams = [], array $headers = []): ServerRequestInterface
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn($serverParams);
        $request->method('getHeaderLine')->willReturnCallback(
            function (string $name) use ($headers): string {
                return $headers[$name] ?? '';
            }
        );

        return $request;
    }
}
