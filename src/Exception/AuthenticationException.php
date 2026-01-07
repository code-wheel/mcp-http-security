<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Exception;

/**
 * Thrown when authentication fails (invalid or missing credentials).
 */
final class AuthenticationException extends SecurityException
{
    public function __construct(
        string $message = 'Authentication required',
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 401, $previous);
    }
}
