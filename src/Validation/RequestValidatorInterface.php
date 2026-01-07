<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Validation;

use CodeWheel\McpSecurity\Exception\ValidationException;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Interface for request validation against security rules.
 */
interface RequestValidatorInterface
{
    /**
     * Validate request against security rules.
     *
     * @throws ValidationException If validation fails
     */
    public function validate(ServerRequestInterface $request): void;

    /**
     * Check if request passes validation (no exception).
     */
    public function isValid(ServerRequestInterface $request): bool;
}
