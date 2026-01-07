<?php

declare(strict_types=1);

namespace CodeWheel\McpSecurity\Tests\Validation;

use CodeWheel\McpSecurity\Validation\IpValidator;
use PHPUnit\Framework\TestCase;

final class IpValidatorTest extends TestCase
{
    public function testEmptyAllowlistAllowsAll(): void
    {
        $validator = new IpValidator([]);

        $this->assertTrue($validator->isAllowed('192.168.1.1'));
        $this->assertTrue($validator->isAllowed('8.8.8.8'));
    }

    public function testExactIpMatch(): void
    {
        $validator = new IpValidator(['192.168.1.1', '10.0.0.1']);

        $this->assertTrue($validator->isAllowed('192.168.1.1'));
        $this->assertTrue($validator->isAllowed('10.0.0.1'));
        $this->assertFalse($validator->isAllowed('192.168.1.2'));
    }

    public function testCidrIpv4(): void
    {
        $validator = new IpValidator(['10.0.0.0/8']);

        $this->assertTrue($validator->isAllowed('10.0.0.1'));
        $this->assertTrue($validator->isAllowed('10.255.255.255'));
        $this->assertFalse($validator->isAllowed('11.0.0.1'));
    }

    public function testCidrIpv4Slash24(): void
    {
        $validator = new IpValidator(['192.168.1.0/24']);

        $this->assertTrue($validator->isAllowed('192.168.1.0'));
        $this->assertTrue($validator->isAllowed('192.168.1.255'));
        $this->assertFalse($validator->isAllowed('192.168.2.1'));
    }

    public function testIpv6Localhost(): void
    {
        $validator = new IpValidator(['::1']);

        $this->assertTrue($validator->isAllowed('::1'));
        $this->assertFalse($validator->isAllowed('::2'));
    }

    public function testIpv6Cidr(): void
    {
        $validator = new IpValidator(['2001:db8::/32']);

        $this->assertTrue($validator->isAllowed('2001:db8::1'));
        $this->assertTrue($validator->isAllowed('2001:db8:ffff::1'));
        $this->assertFalse($validator->isAllowed('2001:db9::1'));
    }

    public function testMixedAllowlist(): void
    {
        $validator = new IpValidator([
            '127.0.0.1',
            '10.0.0.0/8',
            '::1',
        ]);

        $this->assertTrue($validator->isAllowed('127.0.0.1'));
        $this->assertTrue($validator->isAllowed('10.5.3.2'));
        $this->assertTrue($validator->isAllowed('::1'));
        $this->assertFalse($validator->isAllowed('8.8.8.8'));
    }
}
