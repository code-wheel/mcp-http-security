<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Validation;

/**
 * Validates IP addresses against an allowlist.
 *
 * Supports:
 * - Single IPs: 192.168.1.1
 * - CIDR notation: 10.0.0.0/8
 * - IPv6: ::1, 2001:db8::/32
 */
final class IpValidator
{
    /**
     * @param string[] $allowedIps Allowed IP addresses/ranges
     */
    public function __construct(
        private readonly array $allowedIps = [],
    ) {}

    /**
     * Check if IP is allowed.
     *
     * Returns true if:
     * - No allowlist configured (empty = allow all)
     * - IP matches allowlist
     */
    public function isAllowed(string $ip): bool
    {
        if (empty($this->allowedIps)) {
            return true;
        }

        return $this->checkIp($ip, $this->allowedIps);
    }

    /**
     * Check if an IP address matches a list of IPs or subnets.
     *
     * @param string[] $ips List of IPs or subnets
     */
    private function checkIp(string $requestIp, array $ips): bool
    {
        foreach ($ips as $ip) {
            if ($this->checkIpSingle($requestIp, trim($ip))) {
                return true;
            }
        }
        return false;
    }

    private function checkIpSingle(string $requestIp, string $ip): bool
    {
        if (str_contains($ip, '/')) {
            return $this->checkIpCidr($requestIp, $ip);
        }

        return $requestIp === $ip;
    }

    private function checkIpCidr(string $requestIp, string $cidr): bool
    {
        [$subnet, $bits] = explode('/', $cidr, 2);
        $bits = (int) $bits;

        // IPv6
        if (str_contains($subnet, ':')) {
            return $this->checkIpv6($requestIp, $subnet, $bits);
        }

        // IPv4
        return $this->checkIpv4($requestIp, $subnet, $bits);
    }

    private function checkIpv4(string $requestIp, string $subnet, int $bits): bool
    {
        $requestLong = ip2long($requestIp);
        $subnetLong = ip2long($subnet);

        if ($requestLong === false || $subnetLong === false) {
            return false;
        }

        $mask = -1 << (32 - $bits);
        return ($requestLong & $mask) === ($subnetLong & $mask);
    }

    private function checkIpv6(string $requestIp, string $subnet, int $bits): bool
    {
        $requestBin = inet_pton($requestIp);
        $subnetBin = inet_pton($subnet);

        if ($requestBin === false || $subnetBin === false) {
            return false;
        }

        // Compare bit by bit
        $bytes = (int) floor($bits / 8);
        $remainingBits = $bits % 8;

        // Compare full bytes
        if (substr($requestBin, 0, $bytes) !== substr($subnetBin, 0, $bytes)) {
            return false;
        }

        // Compare remaining bits
        if ($remainingBits > 0 && $bytes < 16) {
            $mask = 0xFF << (8 - $remainingBits);
            $requestByte = ord($requestBin[$bytes]);
            $subnetByte = ord($subnetBin[$bytes]);
            if (($requestByte & $mask) !== ($subnetByte & $mask)) {
                return false;
            }
        }

        return true;
    }
}
