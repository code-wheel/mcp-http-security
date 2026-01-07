<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Exception;

/**
 * Thrown when request validation fails (IP/Origin not allowed).
 */
final class ValidationException extends SecurityException
{
    public function __construct(
        string $message = 'Request validation failed',
        ?\Throwable $previous = null,
    ) {
        // Use 404 to avoid revealing security rules
        parent::__construct($message, 404, $previous);
    }
}
