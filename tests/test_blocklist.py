import pytest

from infraprobe.blocklist import BlockedTargetError, InvalidTargetError, validate_domain, validate_ip, validate_target
from infraprobe.target import parse_target


class TestParseTarget:
    def test_plain_domain(self):
        assert parse_target("example.com") == ("example.com", None)

    def test_domain_with_port(self):
        assert parse_target("example.com:8080") == ("example.com", 8080)

    def test_ip(self):
        assert parse_target("93.184.216.34") == ("93.184.216.34", None)

    def test_ip_with_port(self):
        assert parse_target("93.184.216.34:443") == ("93.184.216.34", 443)

    def test_url_with_scheme(self):
        host, port = parse_target("https://example.com:8443")
        assert host == "example.com"
        assert port == 8443

    def test_ipv6_with_port(self):
        assert parse_target("[::1]:8080") == ("::1", 8080)

    def test_url_with_path_and_query(self):
        host, port = parse_target("https://example.com:443/path?q=1")
        assert host == "example.com"
        assert port == 443

    def test_bare_ipv6(self):
        assert parse_target("::1") == ("::1", None)

    def test_bare_ipv4_with_port(self):
        assert parse_target("93.184.216.34:8080") == ("93.184.216.34", 8080)

    def test_is_ip_for_ipv4(self):
        t = parse_target("93.184.216.34")
        assert t.is_ip is True

    def test_is_ip_for_domain(self):
        t = parse_target("example.com")
        assert t.is_ip is False

    def test_is_ip_for_ipv6(self):
        t = parse_target("::1")
        assert t.is_ip is True


class TestValidateTarget:
    async def test_public_domain(self):
        ctx = await validate_target("example.com")
        assert str(ctx) == "example.com"
        assert ctx.is_ip is False
        assert len(ctx.resolved_ips) > 0

    async def test_public_ip(self):
        ctx = await validate_target("93.184.216.34")
        assert str(ctx) == "93.184.216.34"
        assert ctx.is_ip is True
        assert ctx.resolved_ips == ("93.184.216.34",)

    async def test_domain_with_port(self):
        ctx = await validate_target("example.com:443")
        assert str(ctx) == "example.com:443"
        assert ctx.port == 443

    @pytest.mark.parametrize(
        "ip",
        [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "100.64.0.1",  # carrier-grade NAT
            "192.0.2.1",  # TEST-NET-1
            "198.51.100.1",  # TEST-NET-2
            "203.0.113.1",  # TEST-NET-3
        ],
        ids=lambda ip: ip.replace(".", "_"),
    )
    async def test_blocks_ipv4_private(self, ip: str):
        with pytest.raises(BlockedTargetError):
            await validate_target(ip)

    @pytest.mark.parametrize(
        "ip",
        [
            "::1",
            "::ffff:127.0.0.1",  # IPv4-mapped IPv6
            "fc00::1",  # unique local
            "fe80::1",  # link-local
        ],
        ids=["loopback", "v4_mapped", "unique_local", "link_local"],
    )
    async def test_blocks_ipv6_private(self, ip: str):
        with pytest.raises(BlockedTargetError):
            await validate_target(ip)

    async def test_invalid_domain(self):
        with pytest.raises(InvalidTargetError):
            await validate_target("this-domain-definitely-does-not-exist-xyz123.com")


class TestValidateDomain:
    async def test_accepts_domain(self):
        ctx = await validate_domain("example.com")
        assert ctx.is_ip is False
        assert ctx.host == "example.com"

    async def test_rejects_ip(self):
        with pytest.raises(InvalidTargetError, match="Expected a domain"):
            await validate_domain("93.184.216.34")


class TestValidateIp:
    async def test_accepts_ip(self):
        ctx = await validate_ip("93.184.216.34")
        assert ctx.is_ip is True
        assert ctx.host == "93.184.216.34"

    async def test_rejects_domain(self):
        with pytest.raises(InvalidTargetError, match="Expected an IP"):
            await validate_ip("example.com")
