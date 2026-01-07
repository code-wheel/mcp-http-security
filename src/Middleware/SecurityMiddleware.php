<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Middleware;

use CodeWheel\McpSecurity\ApiKey\ApiKey;
use CodeWheel\McpSecurity\ApiKey\ApiKeyManagerInterface;
use CodeWheel\McpSecurity\Config\SecurityConfig;
use CodeWheel\McpSecurity\Exception\AuthenticationException;
use CodeWheel\McpSecurity\Exception\AuthorizationException;
use CodeWheel\McpSecurity\Exception\SecurityException;
use CodeWheel\McpSecurity\Validation\RequestValidatorInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PSR-15 middleware for MCP HTTP security.
 *
 * Handles:
 * - Request validation (IP/Origin allowlists)
 * - API key authentication
 * - Scope authorization
 */
final class SecurityMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly ApiKeyManagerInterface $apiKeyManager,
        private readonly RequestValidatorInterface $requestValidator,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly SecurityConfig $config = new SecurityConfig(),
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        try {
            // Step 1: Validate request (IP/Origin)
            $this->requestValidator->validate($request);

            // Step 2: Authenticate (if required)
            $apiKey = null;
            if ($this->config->requireAuth) {
                $apiKey = $this->authenticate($request);
                $request = $request
                    ->withAttribute($this->config->keyAttribute, $apiKey)
                    ->withAttribute($this->config->scopesAttribute, $apiKey->scopes);
            }

            // Step 3: Authorize scopes (if configured)
            if ($apiKey !== null && !empty($this->config->allowedScopes)) {
                $this->authorize($apiKey);
            }

            return $handler->handle($request);

        } catch (SecurityException $e) {
            return $this->createErrorResponse($e);
        }
    }

    private function authenticate(ServerRequestInterface $request): ApiKey
    {
        $token = $this->extractToken($request);
        if ($token === null) {
            throw new AuthenticationException('API key required');
        }

        $apiKey = $this->apiKeyManager->validate($token);
        if ($apiKey === null) {
            throw new AuthenticationException('Invalid API key');
        }

        return $apiKey;
    }

    private function authorize(ApiKey $apiKey): void
    {
        if (!$apiKey->hasAnyScope($this->config->allowedScopes)) {
            throw new AuthorizationException(
                'Insufficient permissions',
                $this->config->allowedScopes,
                $apiKey->scopes,
            );
        }
    }

    private function extractToken(ServerRequestInterface $request): ?string
    {
        // Try Authorization: Bearer <token>
        $auth = $request->getHeaderLine($this->config->authHeader);
        if (str_starts_with($auth, 'Bearer ')) {
            $token = trim(substr($auth, 7));
            if ($token !== '') {
                return $token;
            }
        }

        // Try X-MCP-Api-Key header
        $apiKey = $request->getHeaderLine($this->config->apiKeyHeader);
        if ($apiKey !== '') {
            return trim($apiKey);
        }

        return null;
    }

    private function createErrorResponse(SecurityException $e): ResponseInterface
    {
        $statusCode = $this->config->silentFail ? 404 : $e->httpStatusCode;
        $response = $this->responseFactory->createResponse($statusCode);

        // Add WWW-Authenticate header for 401 responses
        if ($statusCode === 401) {
            $response = $response->withHeader(
                'WWW-Authenticate',
                'Bearer realm="mcp"'
            );
        }

        // Add Retry-After for rate limit responses
        if ($e instanceof \CodeWheel\McpSecurity\Exception\RateLimitException) {
            $response = $response->withHeader(
                'Retry-After',
                (string) $e->retryAfterSeconds
            );
        }

        $body = $this->config->silentFail
            ? 'Not found'
            : json_encode(['error' => $e->getMessage()], JSON_THROW_ON_ERROR);

        $response->getBody()->write($body);

        return $response
            ->withHeader('Content-Type', $this->config->silentFail ? 'text/plain' : 'application/json')
            ->withHeader('Cache-Control', 'no-store');
    }
}
