# MCP HTTP Security

[![CI](https://github.com/code-wheel/mcp-http-security/actions/workflows/ci.yml/badge.svg)](https://github.com/code-wheel/mcp-http-security/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/code-wheel/mcp-http-security/graph/badge.svg)](https://codecov.io/gh/code-wheel/mcp-http-security)
[![PHPStan](https://img.shields.io/badge/PHPStan-level%209-brightgreen.svg)](https://phpstan.org/)
[![Latest Stable Version](https://poser.pugx.org/code-wheel/mcp-http-security/v)](https://packagist.org/packages/code-wheel/mcp-http-security)
[![PHP Version](https://img.shields.io/packagist/php-v/code-wheel/mcp-http-security.svg)](https://packagist.org/packages/code-wheel/mcp-http-security)
[![License](https://poser.pugx.org/code-wheel/mcp-http-security/license)](https://packagist.org/packages/code-wheel/mcp-http-security)

Secure HTTP transport wrapper for MCP (Model Context Protocol) servers in PHP.

Provides production-ready security components that don't exist elsewhere in the PHP MCP ecosystem:

- **API Key Authentication** - Secure key generation, hashing (SHA-256 + pepper), TTL/expiry
- **IP Allowlisting** - CIDR notation, IPv4/IPv6 support
- **Origin Allowlisting** - Hostname validation with wildcard subdomain support
- **PSR-15 Middleware** - Drop-in security for any PSR-15 compatible framework

## Installation

```bash
composer require code-wheel/mcp-http-security
```

## Quick Start

```php
<?php

use CodeWheel\McpSecurity\ApiKey\ApiKeyManager;
use CodeWheel\McpSecurity\ApiKey\Storage\FileStorage;
use CodeWheel\McpSecurity\Clock\SystemClock;
use CodeWheel\McpSecurity\Config\SecurityConfig;
use CodeWheel\McpSecurity\Middleware\SecurityMiddleware;
use CodeWheel\McpSecurity\Validation\RequestValidator;

// 1. Setup API Key Manager
$storage = new FileStorage('/var/data/mcp-api-keys.json');
$clock = new SystemClock();
$apiKeyManager = new ApiKeyManager(
    storage: $storage,
    clock: $clock,
    pepper: getenv('MCP_API_KEY_PEPPER') ?: '',
);

// 2. Create a key
$result = $apiKeyManager->createKey(
    label: 'Claude Code',
    scopes: ['read', 'write'],
    ttlSeconds: 86400 * 30, // 30 days
);
echo "API Key: {$result['api_key']}\n"; // Show once, store securely

// 3. Setup Request Validator
$validator = new RequestValidator(
    allowedIps: ['127.0.0.1', '10.0.0.0/8'],
    allowedOrigins: ['localhost', '*.example.com'],
);

// 4. Create Middleware
$middleware = new SecurityMiddleware(
    apiKeyManager: $apiKeyManager,
    requestValidator: $validator,
    responseFactory: new HttpFactory(), // Any PSR-17 factory
    config: new SecurityConfig(
        requireAuth: true,
        allowedScopes: ['read', 'write'],
    ),
);

// 5. Use with your PSR-15 application
$app->pipe($middleware);
```

## API Key Management

### Creating Keys

```php
$result = $apiKeyManager->createKey(
    label: 'Production API',
    scopes: ['read', 'write', 'admin'],
    ttlSeconds: null, // No expiry
);

// Returns:
// [
//     'key_id' => 'abc123def456',
//     'api_key' => 'mcp.abc123def456.secret...',
// ]
```

### Listing Keys

```php
$keys = $apiKeyManager->listKeys();

foreach ($keys as $keyId => $key) {
    echo "{$key->label} - Scopes: " . implode(', ', $key->scopes) . "\n";
    echo "  Created: " . date('Y-m-d', $key->created) . "\n";
    echo "  Expires: " . ($key->expires ? date('Y-m-d', $key->expires) : 'Never') . "\n";
}
```

### Validating Keys

```php
$apiKey = $apiKeyManager->validate($tokenFromRequest);

if ($apiKey === null) {
    // Invalid or expired
}

if ($apiKey->hasScope('write')) {
    // Allow write operation
}
```

### Revoking Keys

```php
$apiKeyManager->revokeKey('abc123def456');
```

## Storage Backends

### File Storage (Simple)

```php
use CodeWheel\McpSecurity\ApiKey\Storage\FileStorage;

$storage = new FileStorage('/var/data/api-keys.json');
```

### Database Storage (PDO)

```php
use CodeWheel\McpSecurity\ApiKey\Storage\PdoStorage;

$pdo = new PDO('mysql:host=localhost;dbname=app', 'user', 'pass');
$storage = new PdoStorage($pdo, 'mcp_api_keys');
$storage->ensureTable(); // Creates table if needed
```

### In-Memory (Testing)

```php
use CodeWheel\McpSecurity\ApiKey\Storage\ArrayStorage;

$storage = new ArrayStorage();
```

### Custom Storage

Implement `StorageInterface`:

```php
use CodeWheel\McpSecurity\ApiKey\Storage\StorageInterface;

class RedisStorage implements StorageInterface
{
    public function getAll(): array { /* ... */ }
    public function setAll(array $keys): void { /* ... */ }
    public function get(string $keyId): ?array { /* ... */ }
    public function set(string $keyId, array $data): void { /* ... */ }
    public function delete(string $keyId): bool { /* ... */ }
}
```

## Request Validation

### IP Allowlisting

```php
use CodeWheel\McpSecurity\Validation\IpValidator;

$validator = new IpValidator([
    '127.0.0.1',        // Single IP
    '10.0.0.0/8',       // CIDR range
    '192.168.0.0/16',   // Private network
    '::1',              // IPv6 localhost
]);

$validator->isAllowed('10.5.3.2'); // true
$validator->isAllowed('8.8.8.8');  // false
```

### Origin Allowlisting

```php
use CodeWheel\McpSecurity\Validation\OriginValidator;

$validator = new OriginValidator([
    'localhost',
    'example.com',
    '*.example.com',    // Wildcard: foo.example.com, bar.example.com
]);

$validator->isAllowed('api.example.com'); // true
$validator->isAllowed('evil.com');        // false
```

### Combined Request Validation

```php
use CodeWheel\McpSecurity\Validation\RequestValidator;

$validator = new RequestValidator(
    allowedIps: ['127.0.0.1', '10.0.0.0/8'],
    allowedOrigins: ['localhost', '*.myapp.com'],
);

// With PSR-7 request
$validator->validate($request); // Throws ValidationException if invalid
$validator->isValid($request);  // Returns bool
```

## Middleware Configuration

```php
use CodeWheel\McpSecurity\Config\SecurityConfig;

$config = new SecurityConfig(
    requireAuth: true,           // Require API key
    allowedScopes: ['read'],     // Only allow these scopes
    authHeader: 'Authorization', // Bearer token header
    apiKeyHeader: 'X-MCP-Api-Key', // Alternative header
    scopesAttribute: 'mcp.scopes', // Request attribute for scopes
    keyAttribute: 'mcp.key',     // Request attribute for key info
    silentFail: true,            // Return 404 instead of 401/403
);
```

## Error Handling

The middleware throws typed exceptions:

```php
use CodeWheel\McpSecurity\Exception\AuthenticationException;
use CodeWheel\McpSecurity\Exception\AuthorizationException;
use CodeWheel\McpSecurity\Exception\RateLimitException;
use CodeWheel\McpSecurity\Exception\ValidationException;

try {
    $middleware->process($request, $handler);
} catch (AuthenticationException $e) {
    // 401 - Invalid or missing API key
} catch (AuthorizationException $e) {
    // 403 - Insufficient scopes
    echo "Required: " . implode(', ', $e->requiredScopes);
    echo "Actual: " . implode(', ', $e->actualScopes);
} catch (ValidationException $e) {
    // 404 - IP/Origin not allowed
} catch (RateLimitException $e) {
    // 429 - Rate limited
    echo "Retry after: {$e->retryAfterSeconds} seconds";
}
```

## Framework Integration

### Slim 4

```php
$app->add($securityMiddleware);
```

### Laravel

```php
// In a service provider
$this->app->singleton(SecurityMiddleware::class, function ($app) {
    return new SecurityMiddleware(/* ... */);
});

// In Kernel.php
protected $middleware = [
    \CodeWheel\McpSecurity\Middleware\SecurityMiddleware::class,
];
```

### Drupal

See [drupal/mcp_tools](https://www.drupal.org/project/mcp_tools) which uses this package.

## Security Considerations

1. **Pepper your hashes** - Always provide a pepper for API key hashing
2. **Use HTTPS** - Never transmit API keys over unencrypted connections
3. **Rotate keys** - Use TTL and rotate keys regularly
4. **Least privilege** - Grant minimal scopes needed
5. **Audit logging** - Log key usage for security monitoring

## Examples

See the `examples/` directory for complete working examples:

- **[slim4-integration.php](examples/slim4-integration.php)** - Full Slim 4 framework integration
- **[standalone-validation.php](examples/standalone-validation.php)** - No-framework usage
- **[cli-key-manager.php](examples/cli-key-manager.php)** - CLI tool for managing API keys

## Development

```bash
# Run tests
composer test

# Run tests with coverage
composer test:coverage

# Static analysis (PHPStan level 9)
composer analyse

# Mutation testing
composer infection

# Performance benchmarks
composer benchmark

# Run all CI checks
composer ci
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

## License

MIT License - see [LICENSE](LICENSE) file.

## Credits

Extracted from [drupal/mcp_tools](https://www.drupal.org/project/mcp_tools) by [CodeWheel](https://github.com/code-wheel).

