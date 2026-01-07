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

    public function testInvalidIpv4ReturnsFalse(): void
    {
        $validator = new IpValidator(['192.168.0.0/24']);

        // Invalid IP address format
        $this->assertFalse($validator->isAllowed('not-an-ip'));
        $this->assertFalse($validator->isAllowed('999.999.999.999'));
    }

    public function testInvalidIpv6ReturnsFalse(): void
    {
        $validator = new IpValidator(['2001:db8::/32']);

        // Invalid IPv6 format
        $this->assertFalse($validator->isAllowed('gggg:hhhh::1'));
        $this->assertFalse($validator->isAllowed('not-ipv6'));
    }

    public function testTrimsWhitespace(): void
    {
        $validator = new IpValidator(['  192.168.1.1  ', '  10.0.0.0/8  ']);

        $this->assertTrue($validator->isAllowed('192.168.1.1'));
        $this->assertTrue($validator->isAllowed('10.5.5.5'));
    }

    public function testIpv6PartialByteComparison(): void
    {
        // Test CIDR with non-byte-aligned bits (e.g., /20)
        // 2001:db8::/20 means first 20 bits must match
        // 2001 = 16 bits, then first 4 bits of next group
        // 0db8 starts with 0 (0000), so any 2001:0XXX matches
        $validator = new IpValidator(['2001:db8::/20']);

        $this->assertTrue($validator->isAllowed('2001:db8::1'));
        $this->assertTrue($validator->isAllowed('2001:dff::1')); // 0dff starts with 0
        // 3001 has different first nibble (3 vs 2), so won't match
        $this->assertFalse($validator->isAllowed('3001:db8::1'));
    }

    public function testIpv4Slash0AllowsAll(): void
    {
        $validator = new IpValidator(['0.0.0.0/0']);

        $this->assertTrue($validator->isAllowed('192.168.1.1'));
        $this->assertTrue($validator->isAllowed('8.8.8.8'));
        $this->assertTrue($validator->isAllowed('10.0.0.1'));
    }

    public function testIpv4Slash32SingleIp(): void
    {
        $validator = new IpValidator(['192.168.1.100/32']);

        $this->assertTrue($validator->isAllowed('192.168.1.100'));
        $this->assertFalse($validator->isAllowed('192.168.1.101'));
    }

    public function testIpv6Slash128SingleIp(): void
    {
        $validator = new IpValidator(['2001:db8::1/128']);

        $this->assertTrue($validator->isAllowed('2001:db8::1'));
        $this->assertFalse($validator->isAllowed('2001:db8::2'));
    }

    public function testInvalidSubnetInCidrReturnsFalse(): void
    {
        $validator = new IpValidator(['invalid/24']);

        $this->assertFalse($validator->isAllowed('192.168.1.1'));
    }
}
