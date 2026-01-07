<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Tests\Middleware;

use CodeWheel\McpSecurity\ApiKey\ApiKey;
use CodeWheel\McpSecurity\ApiKey\ApiKeyManagerInterface;
use CodeWheel\McpSecurity\Config\SecurityConfig;
use CodeWheel\McpSecurity\Exception\ValidationException;
use CodeWheel\McpSecurity\Middleware\SecurityMiddleware;
use CodeWheel\McpSecurity\Validation\RequestValidatorInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class SecurityMiddlewareTest extends TestCase
{
    private ApiKeyManagerInterface $apiKeyManager;
    private RequestValidatorInterface $requestValidator;
    private ResponseFactoryInterface $responseFactory;
    private RequestHandlerInterface $handler;
    private ResponseInterface $successResponse;
    private ResponseInterface $errorResponse;
    private StreamInterface $responseBody;

    protected function setUp(): void
    {
        $this->apiKeyManager = $this->createMock(ApiKeyManagerInterface::class);
        $this->requestValidator = $this->createMock(RequestValidatorInterface::class);

        $this->responseBody = $this->createMock(StreamInterface::class);
        $this->responseBody->method('write')->willReturn(10);

        $this->successResponse = $this->createMock(ResponseInterface::class);
        $this->successResponse->method('getStatusCode')->willReturn(200);

        $this->errorResponse = $this->createMock(ResponseInterface::class);
        $this->errorResponse->method('withHeader')->willReturnSelf();
        $this->errorResponse->method('getBody')->willReturn($this->responseBody);

        $this->responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $this->responseFactory->method('createResponse')->willReturn($this->errorResponse);

        $this->handler = $this->createMock(RequestHandlerInterface::class);
        $this->handler->method('handle')->willReturn($this->successResponse);
    }

    public function testProcessPassesRequestWhenValidAndAuthenticated(): void
    {
        $apiKey = new ApiKey('key1', 'Test', ['read'], time());

        $this->requestValidator->expects($this->once())->method('validate');
        $this->apiKeyManager->method('validate')->willReturn($apiKey);

        $request = $this->createRequest(['Authorization' => 'Bearer valid-token']);
        $request->method('withAttribute')->willReturnSelf();

        $middleware = new SecurityMiddleware(
            $this->apiKeyManager,
            $this->requestValidator,
            $this->responseFactory,
        );

        $response = $middleware->process($request, $this->handler);

        $this->assertSame(200, $response->getStatusCode());
    }

    public function testProcessReturns401WhenNoToken(): void
    {
        $this->requestValidator->method('validate');

        $request = $this->createRequest([]);

        $this->responseFactory->expects($this->once())
            ->method('createResponse')
            ->with(401)
            ->willReturn($this->errorResponse);

        $middleware = new SecurityMiddleware(
            $this->apiKeyManager,
            $this->requestValidator,
            $this->responseFactory,
        );

        $middleware->process($request, $this->handler);
    }

    public function testProcessReturns401WhenTokenInvalid(): void
    {
        $this->requestValidator->method('validate');
        $this->apiKeyManager->method('validate')->willReturn(null);

        $request = $this->createRequest(['Authorization' => 'Bearer invalid']);

        $this->responseFactory->expects($this->once())
            ->method('createResponse')
            ->with(401)
            ->willReturn($this->errorResponse);

        $middleware = new SecurityMiddleware(
            $this->apiKeyManager,
            $this->requestValidator,
            $this->responseFactory,
        );

        $middleware->process($request, $this->handler);
    }

    public function testProcessReturns403WhenInsufficientScopes(): void
    {
        $apiKey = new ApiKey('key1', 'Test', ['read'], time());

        $this->requestValidator->method('validate');
        $this->apiKeyManager->method('validate')->willReturn($apiKey);

        $request = $this->createRequest(['Authorization' => 'Bearer valid']);
        $request->method('withAttribute')->willReturnSelf();

        $config = new SecurityConfig(
            requireAuth: true,
            allowedScopes: ['admin'],
        );

        $this->responseFactory->expects($this->once())
            ->method('createResponse')
            ->with(403)
            ->willReturn($this->errorResponse);

        $middleware = new SecurityMiddleware(
            $this->apiKeyManager,
            $this->requestValidator,
            $this->responseFactory,
            $config,
        );

        $middleware->process($request, $this->handler);
    }

    public function testProcessReturns404WhenSilentFailEnabled(): void
    {
        $this->requestValidator->method('validate');

        $request = $this->createRequest([]);

        $config = new SecurityConfig(
            requireAuth: true,
            silentFail: true,
        );

        $this->responseFactory->expects($this->once())
            ->method('createResponse')
            ->with(404)
            ->willReturn($this->errorResponse);

        $middleware = new SecurityMiddleware(
            $this->apiKeyManager,
            $this->requestValidator,
            $this->responseFactory,
            $config,
        );

        $middleware->process($request, $this->handler);
    }

    public function testProcessHandlesValidationExceptionWithSilentFail(): void
    {
        $this->requestValidator->method('validate')
            ->willThrowException(new ValidationException('IP not allowed'));

        $request = $this->createRequest([]);

        $config = new SecurityConfig(silentFail: true);

        $this->responseFactory->expects($this->once())
            ->method('createResponse')
            ->with(404)
            ->willReturn($this->errorResponse);

        $middleware = new SecurityMiddleware(
            $this->apiKeyManager,
            $this->requestValidator,
            $this->responseFactory,
            $config,
        );

        $middleware->process($request, $this->handler);
    }

    public function testProcessHandlesValidationExceptionWithoutSilentFail(): void
    {
        $this->requestValidator->method('validate')
            ->willThrowException(new ValidationException('IP not allowed'));

        $request = $this->createRequest([]);

        // ValidationException already uses 404 by default
        $this->responseFactory->expects($this->once())
            ->method('createResponse')
            ->with(404)
            ->willReturn($this->errorResponse);

        $middleware = new SecurityMiddleware(
            $this->apiKeyManager,
            $this->requestValidator,
            $this->responseFactory,
        );

        $middleware->process($request, $this->handler);
    }

    public function testProcessSkipsAuthWhenNotRequired(): void
    {
        $this->requestValidator->method('validate');

        $request = $this->createRequest([]);

        $config = new SecurityConfig(requireAuth: false);

        $this->handler->expects($this->once())->method('handle');

        $middleware = new SecurityMiddleware(
            $this->apiKeyManager,
            $this->requestValidator,
            $this->responseFactory,
            $config,
        );

        $response = $middleware->process($request, $this->handler);
        $this->assertSame(200, $response->getStatusCode());
    }

    public function testProcessAcceptsTokenFromApiKeyHeader(): void
    {
        $apiKey = new ApiKey('key1', 'Test', ['read'], time());

        $this->requestValidator->method('validate');
        $this->apiKeyManager->method('validate')
            ->with('my-api-key')
            ->willReturn($apiKey);

        $request = $this->createRequest(['X-MCP-Api-Key' => 'my-api-key']);
        $request->method('withAttribute')->willReturnSelf();

        $middleware = new SecurityMiddleware(
            $this->apiKeyManager,
            $this->requestValidator,
            $this->responseFactory,
        );

        $response = $middleware->process($request, $this->handler);
        $this->assertSame(200, $response->getStatusCode());
    }

    public function testProcessSetsRequestAttributes(): void
    {
        $apiKey = new ApiKey('key1', 'Test', ['read', 'write'], time());

        $this->requestValidator->method('validate');
        $this->apiKeyManager->method('validate')->willReturn($apiKey);

        $attributesSet = [];

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getHeaderLine')->willReturnCallback(
            fn(string $name) => $name === 'Authorization' ? 'Bearer token' : ''
        );

        // Use willReturnSelf() and track the attributes being set
        $request->method('withAttribute')
            ->willReturnCallback(function (string $name, $value) use ($request, &$attributesSet) {
                $attributesSet[$name] = $value;
                return $request; // Return self to allow chaining
            });

        $middleware = new SecurityMiddleware(
            $this->apiKeyManager,
            $this->requestValidator,
            $this->responseFactory,
        );

        $middleware->process($request, $this->handler);

        // Verify the attributes were set correctly
        $this->assertArrayHasKey('mcp.key', $attributesSet);
        $this->assertArrayHasKey('mcp.scopes', $attributesSet);
        $this->assertSame($apiKey, $attributesSet['mcp.key']);
        $this->assertSame(['read', 'write'], $attributesSet['mcp.scopes']);
    }

    public function testProcessReturns401WhenBearerTokenIsEmpty(): void
    {
        $this->requestValidator->method('validate');

        // Bearer followed by whitespace only should be treated as no token
        $request = $this->createRequest(['Authorization' => 'Bearer    ']);

        $this->responseFactory->expects($this->once())
            ->method('createResponse')
            ->with(401)
            ->willReturn($this->errorResponse);

        $middleware = new SecurityMiddleware(
            $this->apiKeyManager,
            $this->requestValidator,
            $this->responseFactory,
        );

        $middleware->process($request, $this->handler);
    }

    public function testProcessPassesAuthWhenScopesConfiguredAndMatch(): void
    {
        $apiKey = new ApiKey('key1', 'Test', ['read', 'write'], time());

        $this->requestValidator->method('validate');
        $this->apiKeyManager->method('validate')->willReturn($apiKey);

        $request = $this->createRequest(['Authorization' => 'Bearer valid-token']);
        $request->method('withAttribute')->willReturnSelf();

        $config = new SecurityConfig(
            requireAuth: true,
            allowedScopes: ['read'], // Key has 'read' scope
        );

        $this->handler->expects($this->once())->method('handle');

        $middleware = new SecurityMiddleware(
            $this->apiKeyManager,
            $this->requestValidator,
            $this->responseFactory,
            $config,
        );

        $response = $middleware->process($request, $this->handler);
        $this->assertSame(200, $response->getStatusCode());
    }

    /**
     * @param array<string, string> $headers
     */
    private function createRequest(array $headers): ServerRequestInterface
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getHeaderLine')->willReturnCallback(
            fn(string $name) => $headers[$name] ?? ''
        );
        return $request;
    }
}
