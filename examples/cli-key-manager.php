#!/usr/bin/env php
<?php

/**
 * Example: CLI API Key Manager
 *
 * A simple command-line tool for managing API keys.
 *
 * Usage:
 *   php cli-key-manager.php create "My Key" read,write
 *   php cli-key-manager.php list
 *   php cli-key-manager.php revoke <key_id>
 *   php cli-key-manager.php validate <api_key>
 */

declare(strict_types=1);

use CodeWheel\McpSecurity\ApiKey\ApiKeyManager;
use CodeWheel\McpSecurity\ApiKey\Storage\FileStorage;
use CodeWheel\McpSecurity\Clock\SystemClock;

require __DIR__ . '/../vendor/autoload.php';

// Configuration
$storagePath = getenv('MCP_KEYS_FILE') ?: '/tmp/mcp-api-keys.json';
$pepper = getenv('MCP_API_KEY_PEPPER') ?: 'cli-example-pepper';

// Setup
$storage = new FileStorage($storagePath);
$manager = new ApiKeyManager(
    storage: $storage,
    clock: new SystemClock(),
    pepper: $pepper,
);

// Parse command
$command = $argv[1] ?? 'help';

switch ($command) {
    case 'create':
        $label = $argv[2] ?? 'Unnamed Key';
        $scopesStr = $argv[3] ?? 'read';
        $ttl = isset($argv[4]) ? (int) $argv[4] : null;

        $scopes = array_map('trim', explode(',', $scopesStr));

        $result = $manager->createKey($label, $scopes, $ttl);

        echo "\n✓ API Key created successfully!\n\n";
        echo "  Key ID:  {$result['key_id']}\n";
        echo "  Label:   {$label}\n";
        echo "  Scopes:  " . implode(', ', $scopes) . "\n";
        if ($ttl) {
            echo "  Expires: " . date('Y-m-d H:i:s', time() + $ttl) . "\n";
        }
        echo "\n  API Key: {$result['api_key']}\n";
        echo "\n⚠ Store this key securely - it cannot be retrieved later!\n\n";
        break;

    case 'list':
        $keys = $manager->listKeys();

        if (empty($keys)) {
            echo "\nNo API keys found.\n\n";
            break;
        }

        echo "\nRegistered API Keys:\n";
        echo str_repeat('-', 80) . "\n";
        printf("%-14s %-20s %-25s %s\n", 'Key ID', 'Label', 'Scopes', 'Expires');
        echo str_repeat('-', 80) . "\n";

        foreach ($keys as $keyId => $key) {
            $expires = $key->expires ? date('Y-m-d H:i', $key->expires) : 'Never';
            $scopes = implode(', ', $key->scopes);
            if (strlen($scopes) > 25) {
                $scopes = substr($scopes, 0, 22) . '...';
            }
            printf("%-14s %-20s %-25s %s\n", $keyId, substr($key->label, 0, 20), $scopes, $expires);
        }
        echo str_repeat('-', 80) . "\n";
        echo "Total: " . count($keys) . " key(s)\n\n";
        break;

    case 'revoke':
        $keyId = $argv[2] ?? null;
        if (!$keyId) {
            echo "\nError: Key ID required.\n";
            echo "Usage: php cli-key-manager.php revoke <key_id>\n\n";
            exit(1);
        }

        $key = $manager->getKey($keyId);
        if (!$key) {
            echo "\nError: Key '{$keyId}' not found.\n\n";
            exit(1);
        }

        $manager->revokeKey($keyId);
        echo "\n✓ Key '{$keyId}' ({$key->label}) has been revoked.\n\n";
        break;

    case 'validate':
        $apiKey = $argv[2] ?? null;
        if (!$apiKey) {
            echo "\nError: API key required.\n";
            echo "Usage: php cli-key-manager.php validate <api_key>\n\n";
            exit(1);
        }

        $validated = $manager->validate($apiKey);
        if (!$validated) {
            echo "\n✗ Invalid or expired API key.\n\n";
            exit(1);
        }

        echo "\n✓ Valid API key!\n\n";
        echo "  Key ID:    {$validated->keyId}\n";
        echo "  Label:     {$validated->label}\n";
        echo "  Scopes:    " . implode(', ', $validated->scopes) . "\n";
        echo "  Created:   " . date('Y-m-d H:i:s', $validated->created) . "\n";
        if ($validated->lastUsed) {
            echo "  Last Used: " . date('Y-m-d H:i:s', $validated->lastUsed) . "\n";
        }
        if ($validated->expires) {
            echo "  Expires:   " . date('Y-m-d H:i:s', $validated->expires) . "\n";
        }
        echo "\n";
        break;

    case 'help':
    default:
        echo <<<HELP

MCP API Key Manager
===================

Commands:
  create <label> <scopes> [ttl]  Create a new API key
  list                           List all API keys
  revoke <key_id>                Revoke an API key
  validate <api_key>             Validate an API key

Examples:
  php cli-key-manager.php create "Production API" read,write,admin
  php cli-key-manager.php create "Temp Key" read 3600
  php cli-key-manager.php list
  php cli-key-manager.php revoke abc123def456
  php cli-key-manager.php validate mcp.abc123.secret...

Environment Variables:
  MCP_KEYS_FILE       Path to keys storage file (default: /tmp/mcp-api-keys.json)
  MCP_API_KEY_PEPPER  Pepper for key hashing (required for production)


HELP;
        break;
}
