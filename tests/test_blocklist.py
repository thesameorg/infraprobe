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


class TestValidateTarget:
    def test_public_domain(self):
        result = validate_target("example.com")
        assert result == "example.com"

    def test_public_ip(self):
        result = validate_target("93.184.216.34")
        assert result == "93.184.216.34"

    def test_blocks_localhost(self):
        with pytest.raises(BlockedTargetError):
            validate_target("127.0.0.1")

    def test_blocks_private_10(self):
        with pytest.raises(BlockedTargetError):
            validate_target("10.0.0.1")

    def test_blocks_private_172(self):
        with pytest.raises(BlockedTargetError):
            validate_target("172.16.0.1")

    def test_blocks_private_192(self):
        with pytest.raises(BlockedTargetError):
            validate_target("192.168.1.1")

    def test_blocks_metadata_ip(self):
        with pytest.raises(BlockedTargetError):
            validate_target("169.254.169.254")

    def test_blocks_ipv6_loopback(self):
        with pytest.raises(BlockedTargetError):
            validate_target("::1")

    def test_invalid_domain(self):
        with pytest.raises(InvalidTargetError):
            validate_target("this-domain-definitely-does-not-exist-xyz123.com")

    def test_domain_with_port(self):
        result = validate_target("example.com:443")
        assert result == "example.com:443"
