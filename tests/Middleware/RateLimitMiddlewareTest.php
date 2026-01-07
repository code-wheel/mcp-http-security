<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Tests\Middleware;

use CodeWheel\McpSecurity\ApiKey\ApiKeyManagerInterface;
use CodeWheel\McpSecurity\Config\SecurityConfig;
use CodeWheel\McpSecurity\Exception\RateLimitException;
use CodeWheel\McpSecurity\Middleware\SecurityMiddleware;
use CodeWheel\McpSecurity\Validation\RequestValidatorInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Additional tests for RateLimitException handling in SecurityMiddleware.
 */
final class RateLimitMiddlewareTest extends TestCase
{
    public function testRateLimitExceptionAddsRetryAfterHeader(): void
    {
        $apiKeyManager = $this->createMock(ApiKeyManagerInterface::class);

        $requestValidator = $this->createMock(RequestValidatorInterface::class);
        $requestValidator->method('validate')
            ->willThrowException(new RateLimitException('Too many requests', 120));

        $responseBody = $this->createMock(StreamInterface::class);
        $responseBody->method('write')->willReturn(10);

        $response = $this->createMock(ResponseInterface::class);
        $response->method('getBody')->willReturn($responseBody);

        $headersSet = [];
        $response->method('withHeader')
            ->willReturnCallback(function (string $name, string $value) use ($response, &$headersSet) {
                $headersSet[$name] = $value;
                return $response;
            });

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->method('createResponse')
            ->with(429)
            ->willReturn($response);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getHeaderLine')->willReturn('');

        $handler = $this->createMock(RequestHandlerInterface::class);

        $middleware = new SecurityMiddleware(
            $apiKeyManager,
            $requestValidator,
            $responseFactory,
        );

        $middleware->process($request, $handler);

        $this->assertArrayHasKey('Retry-After', $headersSet);
        $this->assertSame('120', $headersSet['Retry-After']);
    }

    public function testAuthenticationExceptionAddsWwwAuthenticateHeader(): void
    {
        $apiKeyManager = $this->createMock(ApiKeyManagerInterface::class);

        $requestValidator = $this->createMock(RequestValidatorInterface::class);

        $responseBody = $this->createMock(StreamInterface::class);
        $responseBody->method('write')->willReturn(10);

        $response = $this->createMock(ResponseInterface::class);
        $response->method('getBody')->willReturn($responseBody);

        $headersSet = [];
        $response->method('withHeader')
            ->willReturnCallback(function (string $name, string $value) use ($response, &$headersSet) {
                $headersSet[$name] = $value;
                return $response;
            });

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->method('createResponse')
            ->with(401)
            ->willReturn($response);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getHeaderLine')->willReturn('');

        $handler = $this->createMock(RequestHandlerInterface::class);

        $middleware = new SecurityMiddleware(
            $apiKeyManager,
            $requestValidator,
            $responseFactory,
        );

        $middleware->process($request, $handler);

        $this->assertArrayHasKey('WWW-Authenticate', $headersSet);
        $this->assertSame('Bearer realm="mcp"', $headersSet['WWW-Authenticate']);
    }
}
