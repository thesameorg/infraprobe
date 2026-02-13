import pytest

from infraprobe.blocklist import BlockedTargetError, InvalidTargetError, parse_target, validate_target


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


class TestValidateTarget:
    def test_public_domain(self):
        result = validate_target("example.com")
        assert result == "example.com"

    def test_public_ip(self):
        result = validate_target("93.184.216.34")
        assert result == "93.184.216.34"

    def test_domain_with_port(self):
        result = validate_target("example.com:443")
        assert result == "example.com:443"

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
    def test_blocks_ipv4_private(self, ip: str):
        with pytest.raises(BlockedTargetError):
            validate_target(ip)

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
    def test_blocks_ipv6_private(self, ip: str):
        with pytest.raises(BlockedTargetError):
            validate_target(ip)

    def test_invalid_domain(self):
        with pytest.raises(InvalidTargetError):
            validate_target("this-domain-definitely-does-not-exist-xyz123.com")
