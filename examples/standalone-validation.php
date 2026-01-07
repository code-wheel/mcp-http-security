<?php

/**
 * Example: Standalone Validation (No Framework)
 *
 * This example shows how to use the validators without PSR-15 middleware.
 * Useful for CLI tools, custom servers, or non-PSR-15 frameworks.
 */

declare(strict_types=1);

use CodeWheel\McpSecurity\ApiKey\ApiKeyManager;
use CodeWheel\McpSecurity\ApiKey\Storage\ArrayStorage;
use CodeWheel\McpSecurity\Clock\SystemClock;
use CodeWheel\McpSecurity\Validation\IpValidator;
use CodeWheel\McpSecurity\Validation\OriginValidator;

require __DIR__ . '/../vendor/autoload.php';

echo "=== MCP HTTP Security - Standalone Example ===\n\n";

// 1. IP Validation
echo "1. IP Validation\n";
echo str_repeat('-', 40) . "\n";

$ipValidator = new IpValidator([
    '127.0.0.1',        // Localhost
    '10.0.0.0/8',       // Private network
    '192.168.0.0/16',   // Private network
    '::1',              // IPv6 localhost
]);

$testIps = [
    '127.0.0.1',
    '10.5.3.2',
    '192.168.1.100',
    '8.8.8.8',
    '::1',
    '2001:db8::1',
];

foreach ($testIps as $ip) {
    $allowed = $ipValidator->isAllowed($ip) ? 'ALLOWED' : 'BLOCKED';
    echo "  {$ip}: {$allowed}\n";
}

// 2. Origin Validation
echo "\n2. Origin Validation\n";
echo str_repeat('-', 40) . "\n";

$originValidator = new OriginValidator([
    'localhost',
    'example.com',
    '*.example.com',    // Wildcard subdomain
    '*.myapp.io',
]);

$testOrigins = [
    'localhost',
    'example.com',
    'api.example.com',
    'deep.sub.example.com',
    'api.myapp.io',
    'evil.com',
    'example.com.evil.com',
];

foreach ($testOrigins as $origin) {
    $allowed = $originValidator->isAllowed($origin) ? 'ALLOWED' : 'BLOCKED';
    echo "  {$origin}: {$allowed}\n";
}

// 3. Extract hostname from URLs
echo "\n3. Hostname Extraction\n";
echo str_repeat('-', 40) . "\n";

$urls = [
    'https://api.example.com:8080/path?query=1',
    'http://localhost:3000',
    'https://EXAMPLE.COM/PATH',
    'example.com',
];

foreach ($urls as $url) {
    $hostname = $originValidator->extractHostname($url);
    echo "  {$url}\n    -> {$hostname}\n";
}

// 4. API Key Management
echo "\n4. API Key Management\n";
echo str_repeat('-', 40) . "\n";

$storage = new ArrayStorage();
$apiKeyManager = new ApiKeyManager(
    storage: $storage,
    clock: new SystemClock(),
    pepper: 'example-pepper-change-in-production',
);

// Create keys
$key1 = $apiKeyManager->createKey('Admin Key', ['read', 'write', 'admin']);
$key2 = $apiKeyManager->createKey('Read-Only Key', ['read'], ttlSeconds: 3600);
$key3 = $apiKeyManager->createKey('Service Account', ['read', 'write']);

echo "Created keys:\n";
echo "  Admin: {$key1['api_key']}\n";
echo "  Read-Only: {$key2['api_key']}\n";
echo "  Service: {$key3['api_key']}\n";

// Validate key
echo "\nValidating admin key...\n";
$validatedKey = $apiKeyManager->validate($key1['api_key']);
if ($validatedKey) {
    echo "  Valid! Key ID: {$validatedKey->keyId}\n";
    echo "  Label: {$validatedKey->label}\n";
    echo "  Scopes: " . implode(', ', $validatedKey->scopes) . "\n";
    echo "  Has 'admin' scope: " . ($validatedKey->hasScope('admin') ? 'Yes' : 'No') . "\n";
    echo "  Has 'delete' scope: " . ($validatedKey->hasScope('delete') ? 'Yes' : 'No') . "\n";
}

// Test invalid key
echo "\nValidating invalid key...\n";
$invalid = $apiKeyManager->validate('mcp.invalid.key');
echo "  Result: " . ($invalid ? 'Valid' : 'Invalid') . "\n";

// List all keys
echo "\nAll registered keys:\n";
foreach ($apiKeyManager->listKeys() as $keyId => $key) {
    echo "  [{$keyId}] {$key->label}\n";
    echo "    Scopes: " . implode(', ', $key->scopes) . "\n";
    echo "    Expires: " . ($key->expires ? date('Y-m-d H:i:s', $key->expires) : 'Never') . "\n";
}

// Revoke a key
echo "\nRevoking read-only key...\n";
$revoked = $apiKeyManager->revokeKey($key2['key_id']);
echo "  Revoked: " . ($revoked ? 'Yes' : 'No') . "\n";

// Verify it's gone
$afterRevoke = $apiKeyManager->validate($key2['api_key']);
echo "  Still valid: " . ($afterRevoke ? 'Yes' : 'No') . "\n";

echo "\n=== Done ===\n";
