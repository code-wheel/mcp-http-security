<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Exception;

use Exception;

/**
 * Base exception for security-related errors.
 */
class SecurityException extends Exception
{
    public function __construct(
        string $message,
        public readonly int $httpStatusCode = 403,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
