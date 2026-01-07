<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Exception;

/**
 * Thrown when rate limit is exceeded.
 */
final class RateLimitException extends SecurityException
{
    public function __construct(
        string $message = 'Rate limit exceeded',
        public readonly int $retryAfterSeconds = 60,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 429, $previous);
    }
}
