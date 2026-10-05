"""Unit tests for the pre-navigation URL-only feature extractor."""

import math
import socket
import urllib.request
import pytest

from api_detection.features.url_features import (
    FEATURE_NAMES,
    extract_url_features,
    extract_url_feature_vector,
    shannon_entropy,
)


def test_feature_names_order_and_types():
    assert isinstance(FEATURE_NAMES, tuple)
    assert len(FEATURE_NAMES) == 29
    # All names must be unique
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)


def test_normal_https_url():
    url = "https://www.google.com/search?q=cybersecurity"
    feats = extract_url_features(url)
    vec = extract_url_feature_vector(url)

    assert len(feats) == len(FEATURE_NAMES)
    assert len(vec) == len(FEATURE_NAMES)
    assert feats["is_https"] == 1.0
    assert feats["has_ip"] == 0.0
    assert feats["has_ipv4"] == 0.0
    assert feats["has_ipv6"] == 0.0
    assert feats["has_at_symbol"] == 0.0
    assert feats["has_punycode"] == 0.0
    assert feats["has_double_slash_redirect"] == 0.0
    assert feats["is_shortener"] == 0.0
    assert feats["num_dots_hostname"] == 2.0
    assert feats["hostname_length"] == len("www.google.com")
    assert feats["query_length"] == len("q=cybersecurity")
    assert feats["path_length"] == len("/search")


def test_http_url():
    url = "http://example.org/index.html"
    feats = extract_url_features(url)

    assert feats["is_https"] == 0.0
    assert feats["has_ip"] == 0.0
    assert feats["num_dots_hostname"] == 1.0
    assert feats["path_length"] == len("/index.html")
    assert feats["query_length"] == 0.0


def test_url_containing_ipv4_address():
    url = "http://192.168.1.100:8080/admin/login"
    feats = extract_url_features(url)

    assert feats["has_ipv4"] == 1.0
    assert feats["has_ipv6"] == 0.0
    assert feats["has_ip"] == 1.0
    assert feats["num_subdomains"] == 0.0
    assert feats["num_digits_hostname"] == 10.0


def test_url_containing_ipv6_address():
    url = "http://[2001:db8::1]:80/status"
    feats = extract_url_features(url)

    assert feats["has_ipv4"] == 0.0
    assert feats["has_ipv6"] == 1.0
    assert feats["has_ip"] == 1.0
    assert feats["num_subdomains"] == 0.0


def test_url_containing_at_symbol():
    url = "http://legit-service.com@evil-attacker.com/steal"
    feats = extract_url_features(url)

    assert feats["has_at_symbol"] == 1.0
    assert feats["hostname_length"] == len("evil-attacker.com")
    assert feats["has_ip"] == 0.0


def test_punycode_url():
    # xn-- internationalized domain name
    url = "https://xn--apple-43d.com/secure-login"
    feats = extract_url_features(url)

    assert feats["has_punycode"] == 1.0
    assert feats["num_hyphens"] >= 2.0


def test_suspicious_keywords_and_tld():
    url = "http://secure-paypal-login-verification.xyz/account/confirm"
    feats = extract_url_features(url)

    assert feats["has_suspicious_tld"] == 1.0  # .xyz is in SUSPICIOUS_TLDS
    # Matches 'secure', 'paypal', 'login', 'verification', 'account', 'confirm'
    assert feats["suspicious_keyword_count"] >= 4.0
    assert feats["num_hyphens"] >= 3.0


def test_many_subdomains():
    url = "https://a.b.c.d.banking.example.com/portal"
    feats = extract_url_features(url)

    # 6 parts in hostname: a, b, c, d, banking, example, com -> 7 - 2 = 5 subdomains
    assert feats["num_subdomains"] >= 4.0
    assert feats["num_dots_hostname"] >= 5.0


def test_long_and_high_entropy_url():
    # Long random hex/base64-like path
    url = "https://legit.com/session/a8f9c1b2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7?token=XyZ9910AzLkQ=="
    feats = extract_url_features(url)

    assert feats["url_length"] > 70.0
    assert feats["url_entropy"] > 4.0
    assert feats["digit_ratio"] > 0.15
    assert feats["special_char_ratio"] > 0.0


def test_url_shortener_indicator():
    url = "https://bit.ly/3xYqz7"
    feats = extract_url_features(url)

    assert feats["is_shortener"] == 1.0

    url2 = "http://tinyurl.com/fake-login"
    feats2 = extract_url_features(url2)
    assert feats2["is_shortener"] == 1.0


def test_double_slash_redirect():
    url = "http://legit-site.com//evil-domain.com/phish"
    feats = extract_url_features(url)

    assert feats["has_double_slash_redirect"] == 1.0


def test_empty_and_malformed_url():
    # Empty string
    empty_feats = extract_url_features("")
    assert empty_feats["url_length"] == 0.0
    assert empty_feats["url_entropy"] == 0.0
    assert empty_feats["has_ip"] == 0.0

    # Whitespace only
    ws_feats = extract_url_features("   ")
    assert ws_feats["url_length"] == 0.0

    # Malformed URL without scheme or host
    malformed = extract_url_features(":::not_a_valid_url???")
    assert isinstance(malformed, dict)
    assert len(malformed) == len(FEATURE_NAMES)
    assert malformed["url_length"] > 0.0


def test_feature_determinism():
    url = "https://auth.security-update.accountant/verify?user=victim&session=99281#frag"
    feats1 = extract_url_features(url)
    feats2 = extract_url_features(url)
    vec1 = extract_url_feature_vector(url)
    vec2 = extract_url_feature_vector(url)

    assert feats1 == feats2
    assert vec1 == vec2
    assert len(vec1) == len(FEATURE_NAMES)


def test_strictly_zero_network_activity(monkeypatch):
    """
    Ensure the extractor NEVER attempts socket creation, DNS resolution,
    or HTTP connections under any circumstances.
    """
    def forbidden_call(*args, **kwargs):
        pytest.fail("SECURITY VIOLATION: URL feature extractor attempted network/socket activity!")

    # Intercept raw socket creation and DNS resolution
    monkeypatch.setattr(socket, "socket", forbidden_call)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden_call)
    monkeypatch.setattr(socket, "gethostbyname", forbidden_call)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden_call)

    # Test variety of complex URLs
    test_urls = [
        "https://www.google.com/search?q=test",
        "http://192.168.0.1/admin",
        "http://[2001:db8::1]:8080/test",
        "https://bit.ly/secure-login",
        "http://attacker.tk/verify-account",
        "http://user@domain.com//redirect",
        "https://xn--pple-43d.com/login",
    ]

    for url in test_urls:
        feats = extract_url_features(url)
        assert len(feats) == len(FEATURE_NAMES)
        vec = extract_url_feature_vector(url)
        assert len(vec) == len(FEATURE_NAMES)
