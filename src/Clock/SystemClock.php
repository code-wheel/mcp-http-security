<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Clock;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/**
 * Simple system clock implementation.
 */
final class SystemClock implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable();
    }
}
