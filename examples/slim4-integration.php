<?php

/**
 * Example: Slim 4 Integration
 *
 * This example shows how to integrate MCP HTTP Security with Slim 4.
 *
 * Requirements:
 *   composer require slim/slim slim/psr7
 */

declare(strict_types=1);

use CodeWheel\McpSecurity\ApiKey\ApiKeyManager;
use CodeWheel\McpSecurity\ApiKey\Storage\FileStorage;
use CodeWheel\McpSecurity\Clock\SystemClock;
use CodeWheel\McpSecurity\Config\SecurityConfig;
use CodeWheel\McpSecurity\Middleware\SecurityMiddleware;
use CodeWheel\McpSecurity\Validation\RequestValidator;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;

require __DIR__ . '/../vendor/autoload.php';

// 1. Setup storage and API key manager
$storage = new FileStorage('/tmp/mcp-api-keys.json');
$apiKeyManager = new ApiKeyManager(
    storage: $storage,
    clock: new SystemClock(),
    pepper: getenv('MCP_API_KEY_PEPPER') ?: 'change-me-in-production',
);

// 2. Create a test key (do this once, then remove)
if (!file_exists('/tmp/mcp-api-keys.json')) {
    $result = $apiKeyManager->createKey(
        label: 'Test Key',
        scopes: ['read', 'write'],
    );
    echo "Created API Key: {$result['api_key']}\n";
    echo "Store this securely - it won't be shown again!\n\n";
}

// 3. Setup request validator
$validator = new RequestValidator(
    allowedIps: [], // Empty = allow all IPs
    allowedOrigins: [], // Empty = allow all origins
);

// 4. Create Slim app
$app = AppFactory::create();

// 5. Add security middleware
$securityMiddleware = new SecurityMiddleware(
    apiKeyManager: $apiKeyManager,
    requestValidator: $validator,
    responseFactory: $app->getResponseFactory(),
    config: new SecurityConfig(
        requireAuth: true,
        allowedScopes: ['read', 'write'],
    ),
);

$app->add($securityMiddleware);

// 6. Define routes
$app->get('/', function (Request $request, Response $response): Response {
    // Access the authenticated API key
    $apiKey = $request->getAttribute('mcp.key');
    $scopes = $request->getAttribute('mcp.scopes');

    $data = [
        'message' => 'Hello from secured MCP endpoint!',
        'key_id' => $apiKey->keyId,
        'label' => $apiKey->label,
        'scopes' => $scopes,
    ];

    $response->getBody()->write(json_encode($data, JSON_PRETTY_PRINT));
    return $response->withHeader('Content-Type', 'application/json');
});

$app->get('/keys', function (Request $request, Response $response) use ($apiKeyManager): Response {
    $keys = [];
    foreach ($apiKeyManager->listKeys() as $keyId => $key) {
        $keys[] = [
            'key_id' => $keyId,
            'label' => $key->label,
            'scopes' => $key->scopes,
            'created' => date('c', $key->created),
            'expires' => $key->expires ? date('c', $key->expires) : null,
        ];
    }

    $response->getBody()->write(json_encode($keys, JSON_PRETTY_PRINT));
    return $response->withHeader('Content-Type', 'application/json');
});

// 7. Run the app
$app->run();

/*
 * Usage:
 *
 * 1. Run the server:
 *    php -S localhost:8080 examples/slim4-integration.php
 *
 * 2. Make authenticated requests:
 *    curl -H "Authorization: Bearer mcp.xxx.yyy" http://localhost:8080/
 *    curl -H "X-MCP-Api-Key: mcp.xxx.yyy" http://localhost:8080/keys
 *
 * 3. Without auth (will get 401):
 *    curl http://localhost:8080/
 */
