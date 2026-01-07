<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Tests\Clock;

use CodeWheel\McpSecurity\Clock\SystemClock;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;

final class SystemClockTest extends TestCase
{
    public function testImplementsClockInterface(): void
    {
        $clock = new SystemClock();

        $this->assertInstanceOf(ClockInterface::class, $clock);
    }

    public function testNowReturnsDateTimeImmutable(): void
    {
        $clock = new SystemClock();

        $result = $clock->now();

        $this->assertInstanceOf(DateTimeImmutable::class, $result);
    }

    public function testNowReturnsCurrentTime(): void
    {
        $clock = new SystemClock();
        $before = time();

        $result = $clock->now();

        $after = time();

        $timestamp = $result->getTimestamp();
        $this->assertGreaterThanOrEqual($before, $timestamp);
        $this->assertLessThanOrEqual($after, $timestamp);
    }

    public function testNowReturnsNewInstanceEachCall(): void
    {
        $clock = new SystemClock();

        $first = $clock->now();
        $second = $clock->now();

        $this->assertNotSame($first, $second);
    }

    public function testNowHasMicrosecondPrecision(): void
    {
        $clock = new SystemClock();

        $result = $clock->now();

        // DateTimeImmutable should have microsecond precision
        $formatted = $result->format('u');
        $this->assertSame(6, strlen($formatted));
    }
}
