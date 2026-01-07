<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Validation;

use CodeWheel\McpSecurity\Exception\ValidationException;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Validates requests against IP and Origin allowlists.
 */
final class RequestValidator implements RequestValidatorInterface
{
    private readonly IpValidator $ipValidator;
    private readonly OriginValidator $originValidator;

    /**
     * @param string[] $allowedIps IP addresses/ranges to allow
     * @param string[] $allowedOrigins Hostnames/patterns to allow
     */
    public function __construct(
        array $allowedIps = [],
        array $allowedOrigins = [],
        ?IpValidator $ipValidator = null,
        ?OriginValidator $originValidator = null,
    ) {
        $this->ipValidator = $ipValidator ?? new IpValidator($allowedIps);
        $this->originValidator = $originValidator ?? new OriginValidator($allowedOrigins);
    }

    public function validate(ServerRequestInterface $request): void
    {
        // Check IP
        $clientIp = $this->getClientIp($request);
        if ($clientIp !== null && !$this->ipValidator->isAllowed($clientIp)) {
            throw new ValidationException('IP not allowed');
        }

        // Check Origin
        $hostname = $this->getRequestHostname($request);
        if ($hostname !== null && !$this->originValidator->isAllowed($hostname)) {
            throw new ValidationException('Origin not allowed');
        }
    }

    public function isValid(ServerRequestInterface $request): bool
    {
        try {
            $this->validate($request);
            return true;
        } catch (ValidationException) {
            return false;
        }
    }

    /**
     * Extract client IP from request.
     *
     * Uses X-Forwarded-For if present (trusted proxies), falls back to
     * REMOTE_ADDR from server params.
     */
    private function getClientIp(ServerRequestInterface $request): ?string
    {
        // Check X-Forwarded-For (first IP is original client)
        $forwarded = $request->getHeaderLine('X-Forwarded-For');
        if ($forwarded !== '') {
            $ips = array_map('trim', explode(',', $forwarded));
            $clientIp = $ips[0] ?? null;
            if ($clientIp !== null && $clientIp !== '') {
                return $clientIp;
            }
        }

        // Fall back to REMOTE_ADDR
        $serverParams = $request->getServerParams();
        $remoteAddr = $serverParams['REMOTE_ADDR'] ?? null;
        return is_string($remoteAddr) && $remoteAddr !== '' ? $remoteAddr : null;
    }

    /**
     * Extract hostname for origin validation.
     *
     * Priority: Origin header > Referer header > Host header
     */
    private function getRequestHostname(ServerRequestInterface $request): ?string
    {
        // Try Origin header first (sent by browsers for CORS)
        $origin = $request->getHeaderLine('Origin');
        if ($origin !== '') {
            return $this->originValidator->extractHostname($origin);
        }

        // Try Referer header
        $referer = $request->getHeaderLine('Referer');
        if ($referer !== '') {
            return $this->originValidator->extractHostname($referer);
        }

        // Fall back to Host header
        $host = $request->getHeaderLine('Host');
        if ($host !== '') {
            // Remove port if present
            $colonPos = strrpos($host, ':');
            if ($colonPos !== false) {
                $host = substr($host, 0, $colonPos);
            }
            return strtolower($host);
        }

        return null;
    }
}
