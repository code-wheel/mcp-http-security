<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\ApiKey;

/**
 * Value object representing a validated API key.
 */
final class ApiKey
{
    /**
     * @param string[] $scopes
     */
    public function __construct(
        public readonly string $keyId,
        public readonly string $label,
        public readonly array $scopes,
        public readonly int $created,
        public readonly ?int $lastUsed = null,
        public readonly ?int $expires = null,
    ) {}

    /**
     * Check if this key has a specific scope.
     */
    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }

    /**
     * Check if this key has any of the given scopes.
     *
     * @param string[] $scopes
     */
    public function hasAnyScope(array $scopes): bool
    {
        return !empty(array_intersect($this->scopes, $scopes));
    }

    /**
     * Check if this key has all of the given scopes.
     *
     * @param string[] $scopes
     */
    public function hasAllScopes(array $scopes): bool
    {
        return empty(array_diff($scopes, $this->scopes));
    }

    /**
     * Check if this key is expired.
     */
    public function isExpired(int $currentTime): bool
    {
        if ($this->expires === null) {
            return false;
        }
        return $this->expires < $currentTime;
    }
}
