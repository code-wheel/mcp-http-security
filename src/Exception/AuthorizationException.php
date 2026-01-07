<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Exception;

/**
 * Thrown when authorization fails (insufficient permissions/scopes).
 */
final class AuthorizationException extends SecurityException
{
    /**
     * @param string[] $requiredScopes
     * @param string[] $actualScopes
     */
    public function __construct(
        string $message = 'Insufficient permissions',
        public readonly array $requiredScopes = [],
        public readonly array $actualScopes = [],
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 403, $previous);
    }
}
