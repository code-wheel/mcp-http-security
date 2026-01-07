<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Tests\Exception;

use CodeWheel\McpSecurity\Exception\AuthenticationException;
use CodeWheel\McpSecurity\Exception\AuthorizationException;
use CodeWheel\McpSecurity\Exception\RateLimitException;
use CodeWheel\McpSecurity\Exception\SecurityException;
use CodeWheel\McpSecurity\Exception\ValidationException;
use PHPUnit\Framework\TestCase;

final class ExceptionTest extends TestCase
{
    public function testSecurityExceptionDefaults(): void
    {
        $exception = new SecurityException('Test error');

        $this->assertSame('Test error', $exception->getMessage());
        $this->assertSame(403, $exception->httpStatusCode);
        $this->assertNull($exception->getPrevious());
    }

    public function testSecurityExceptionCustomStatusCode(): void
    {
        $exception = new SecurityException('Custom', 500);

        $this->assertSame(500, $exception->httpStatusCode);
    }

    public function testSecurityExceptionWithPrevious(): void
    {
        $previous = new \RuntimeException('Previous');
        $exception = new SecurityException('Test', 403, $previous);

        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testAuthenticationExceptionDefaults(): void
    {
        $exception = new AuthenticationException();

        $this->assertSame('Authentication required', $exception->getMessage());
        $this->assertSame(401, $exception->httpStatusCode);
    }

    public function testAuthenticationExceptionCustomMessage(): void
    {
        $exception = new AuthenticationException('Invalid token');

        $this->assertSame('Invalid token', $exception->getMessage());
        $this->assertSame(401, $exception->httpStatusCode);
    }

    public function testAuthenticationExceptionWithPrevious(): void
    {
        $previous = new \RuntimeException('Previous');
        $exception = new AuthenticationException('Test', $previous);

        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testAuthorizationExceptionDefaults(): void
    {
        $exception = new AuthorizationException();

        $this->assertSame('Insufficient permissions', $exception->getMessage());
        $this->assertSame(403, $exception->httpStatusCode);
        $this->assertSame([], $exception->requiredScopes);
        $this->assertSame([], $exception->actualScopes);
    }

    public function testAuthorizationExceptionWithScopes(): void
    {
        $exception = new AuthorizationException(
            'Access denied',
            ['admin', 'write'],
            ['read'],
        );

        $this->assertSame('Access denied', $exception->getMessage());
        $this->assertSame(['admin', 'write'], $exception->requiredScopes);
        $this->assertSame(['read'], $exception->actualScopes);
    }

    public function testAuthorizationExceptionWithPrevious(): void
    {
        $previous = new \RuntimeException('Previous');
        $exception = new AuthorizationException('Test', [], [], $previous);

        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testRateLimitExceptionDefaults(): void
    {
        $exception = new RateLimitException();

        $this->assertSame('Rate limit exceeded', $exception->getMessage());
        $this->assertSame(429, $exception->httpStatusCode);
        $this->assertSame(60, $exception->retryAfterSeconds);
    }

    public function testRateLimitExceptionCustomValues(): void
    {
        $exception = new RateLimitException('Too many requests', 120);

        $this->assertSame('Too many requests', $exception->getMessage());
        $this->assertSame(120, $exception->retryAfterSeconds);
    }

    public function testRateLimitExceptionWithPrevious(): void
    {
        $previous = new \RuntimeException('Previous');
        $exception = new RateLimitException('Test', 60, $previous);

        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testValidationExceptionInheritsFromSecurity(): void
    {
        $exception = new ValidationException('IP not allowed');

        $this->assertInstanceOf(SecurityException::class, $exception);
        $this->assertSame('IP not allowed', $exception->getMessage());
        // ValidationException uses 404 to hide security rules
        $this->assertSame(404, $exception->httpStatusCode);
    }

    public function testValidationExceptionDefaults(): void
    {
        $exception = new ValidationException();

        $this->assertSame('Request validation failed', $exception->getMessage());
        $this->assertSame(404, $exception->httpStatusCode);
    }

    public function testValidationExceptionWithPrevious(): void
    {
        $previous = new \RuntimeException('Previous');
        $exception = new ValidationException('Test', $previous);

        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testExceptionHierarchy(): void
    {
        $this->assertInstanceOf(\Exception::class, new SecurityException(''));
        $this->assertInstanceOf(SecurityException::class, new AuthenticationException());
        $this->assertInstanceOf(SecurityException::class, new AuthorizationException());
        $this->assertInstanceOf(SecurityException::class, new RateLimitException());
        $this->assertInstanceOf(SecurityException::class, new ValidationException(''));
    }
}
