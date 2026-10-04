"""Deterministic, pre-navigation URL-only feature extractor.

SECURITY CONSTRAINT:
This module must NEVER make network requests (HTTP, DNS, WHOIS), inspect DOM/HTML,
or call external APIs. All features are derived strictly from the URL string itself.
"""

from __future__ import annotations

from collections import Counter
import ipaddress
import math
import re
from typing import Any
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Stable Feature Definitions (ordering MUST remain frozen for ML consistency)
# ---------------------------------------------------------------------------
FEATURE_NAMES: tuple[str, ...] = (
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "fragment_length",
    "num_dots",
    "num_dots_hostname",
    "num_hyphens",
    "num_hyphens_hostname",
    "num_digits",
    "num_digits_hostname",
    "num_special_chars",
    "num_subdomains",
    "has_ipv4",
    "has_ipv6",
    "has_ip",
    "has_at_symbol",
    "has_double_slash_redirect",
    "has_punycode",
    "is_https",
    "has_suspicious_tld",
    "suspicious_keyword_count",
    "is_shortener",
    "digit_ratio",
    "special_char_ratio",
    "url_entropy",
    "hostname_entropy",
    "path_entropy",
    "query_entropy",
)

# ---------------------------------------------------------------------------
# Knowledge Signatures (Deterministic String Lookups)
# ---------------------------------------------------------------------------
SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "buzz",
        "top",
        "xyz",
        "work",
        "surf",
        "fit",
        "icu",
        "country",
        "cam",
        "link",
        "click",
        "rest",
        "tokyo",
        "vip",
        "monster",
        "mom",
        "live",
        "bar",
        "bid",
        "racing",
        "date",
        "review",
        "stream",
        "trade",
        "download",
        "win",
        "accountant",
        "cricket",
        "party",
    }
)

SUSPICIOUS_KEYWORDS: tuple[str, ...] = (
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "security",
    "update",
    "banking",
    "secure",
    "account",
    "confirm",
    "confirmation",
    "password",
    "credential",
    "wallet",
    "support",
    "service",
    "billing",
    "authenticate",
    "authentication",
    "portal",
    "admin",
    "authorize",
    "payment",
    "recover",
    "suspend",
    "appleid",
    "paypal",
    "microsoft",
    "google",
    "netflix",
    "amazon",
)

KNOWN_SHORTENERS: frozenset[str] = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "adf.ly",
        "bit.do",
        "rebrand.ly",
        "shorte.st",
        "tiny.cc",
        "bc.vc",
        "tr.im",
        "cutt.ly",
        "v.gd",
        "trib.al",
        "s.id",
    }
)

SPECIAL_CHAR_REGEX: re.Pattern[str] = re.compile(r"[^a-zA-Z0-9.\-/]")


def shannon_entropy(s: str) -> float:
    """Calculate the Shannon entropy of a string (bits per character)."""
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _split_url(raw_url: str) -> tuple[str, str, str, str, str, str]:
    """
    Safely split a URL string into components without raising exceptions.
    Returns (scheme, netloc, hostname, path, query, fragment).
    """
    s = (raw_url or "").strip()
    if not s:
        return "", "", "", "", "", ""

    # If scheme is absent, assist urlsplit by adding a synthetic prefix for structure
    has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", s))
    if not has_scheme:
        split_result = urlsplit(f"http://{s}")
        scheme = ""
    else:
        split_result = urlsplit(s)
        scheme = split_result.scheme.lower()

    netloc = split_result.netloc.lower()
    path = split_result.path
    query = split_result.query
    fragment = split_result.fragment

    # Extract hostname from netloc (strip port and userinfo)
    hostname = netloc
    if "@" in hostname:
        hostname = hostname.split("@", 1)[1]
    if ":" in hostname:
        # IPv6 enclosed in brackets
        if hostname.startswith("[") and "]" in hostname:
            hostname = hostname[1 : hostname.index("]")]
        else:
            hostname = hostname.split(":", 1)[0]

    return scheme, netloc, hostname, path, query, fragment


def _check_ip_address(hostname: str) -> tuple[bool, bool]:
    """Check if the hostname is a valid IPv4 or IPv6 address."""
    if not hostname:
        return False, False

    clean_host = hostname.strip("[]")
    is_ipv4 = False
    is_ipv6 = False

    try:
        ip = ipaddress.ip_address(clean_host)
        if isinstance(ip, ipaddress.IPv4Address):
            is_ipv4 = True
        elif isinstance(ip, ipaddress.IPv6Address):
            is_ipv6 = True
    except ValueError:
        pass

    return is_ipv4, is_ipv6


def extract_url_features(url: str) -> dict[str, float]:
    """
    Extract a deterministic dictionary of URL-only numerical features.

    Zero network lookups, zero external requests, zero DOM/HTML inspection.
    """
    url_str = (url or "").strip()
    scheme, netloc, hostname, path, query, fragment = _split_url(url_str)

    url_len = float(len(url_str))
    host_len = float(len(hostname))
    path_len = float(len(path))
    query_len = float(len(query))
    frag_len = float(len(fragment))

    # Dot counts
    num_dots = float(url_str.count("."))
    num_dots_host = float(hostname.count("."))

    # Hyphen counts
    num_hyphens = float(url_str.count("-"))
    num_hyphens_host = float(hostname.count("-"))

    # Digit counts
    num_digits = float(sum(c.isdigit() for c in url_str))
    num_digits_host = float(sum(c.isdigit() for c in hostname))

    # Special characters (characters outside alphanumeric, dot, hyphen, slash)
    num_special = float(len(SPECIAL_CHAR_REGEX.findall(url_str)))

    # IP address evaluation
    is_ipv4, is_ipv6 = _check_ip_address(hostname)
    has_ip = is_ipv4 or is_ipv6

    # Subdomain calculation
    # If it's an IP, subdomains = 0
    if has_ip or not hostname:
        num_subdomains = 0.0
    else:
        parts = [p for p in hostname.split(".") if p]
        # e.g., 'example.com' has 2 parts -> 0 subdomains; 'sub.example.com' has 3 -> 1 subdomain
        num_subdomains = float(max(0, len(parts) - 2))

    # Syntax flags
    has_at = 1.0 if "@" in url_str else 0.0

    # Suspicious double slash after scheme (e.g., http://example.com//phish or http://trusted.com//evil.com)
    # The normal position of // is at index 5 or 6 (http:// or https://)
    # If // appears later in the string, it indicates a redirection trick
    first_slash_slash = url_str.find("//")
    last_slash_slash = url_str.rfind("//")
    has_double_slash_redirect = (
        1.0 if (last_slash_slash > 7 or (first_slash_slash > 0 and first_slash_slash != url_str.find("://") + 1 and not url_str.startswith("//"))) else 0.0
    )

    has_punycode = 1.0 if "xn--" in hostname else 0.0
    is_https_val = 1.0 if scheme == "https" else 0.0

    # Suspicious TLD check
    tld = hostname.rsplit(".", 1)[-1].lower() if "." in hostname and not has_ip else ""
    has_susp_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0

    # Keyword hits in URL
    url_lower = url_str.lower()
    keyword_hits = float(
        sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    )

    # URL shortener check
    is_short = 1.0 if (hostname in KNOWN_SHORTENERS or any(hostname.endswith(f".{s}") for s in KNOWN_SHORTENERS)) else 0.0

    # Ratios
    denom = max(url_len, 1.0)
    digit_ratio = num_digits / denom
    special_char_ratio = num_special / denom

    # Entropies
    url_ent = shannon_entropy(url_str)
    host_ent = shannon_entropy(hostname)
    path_ent = shannon_entropy(path)
    query_ent = shannon_entropy(query)

    features: dict[str, float] = {
        "url_length": url_len,
        "hostname_length": host_len,
        "path_length": path_len,
        "query_length": query_len,
        "fragment_length": frag_len,
        "num_dots": num_dots,
        "num_dots_hostname": num_dots_host,
        "num_hyphens": num_hyphens,
        "num_hyphens_hostname": num_hyphens_host,
        "num_digits": num_digits,
        "num_digits_hostname": num_digits_host,
        "num_special_chars": num_special,
        "num_subdomains": num_subdomains,
        "has_ipv4": 1.0 if is_ipv4 else 0.0,
        "has_ipv6": 1.0 if is_ipv6 else 0.0,
        "has_ip": 1.0 if has_ip else 0.0,
        "has_at_symbol": has_at,
        "has_double_slash_redirect": has_double_slash_redirect,
        "has_punycode": has_punycode,
        "is_https": is_https_val,
        "has_suspicious_tld": has_susp_tld,
        "suspicious_keyword_count": keyword_hits,
        "is_shortener": is_short,
        "digit_ratio": digit_ratio,
        "special_char_ratio": special_char_ratio,
        "url_entropy": url_ent,
        "hostname_entropy": host_ent,
        "path_entropy": path_ent,
        "query_entropy": query_ent,
    }

    return features


def extract_url_feature_vector(url: str) -> list[float]:
    """
    Extract a dense numerical feature vector ordered strictly according to FEATURE_NAMES.
    Compatible with scikit-learn / XGBoost model inference.
    """
    feature_dict = extract_url_features(url)
    return [feature_dict[name] for name in FEATURE_NAMES]
