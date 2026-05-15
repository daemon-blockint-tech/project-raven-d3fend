"""
Unit tests for pipeline.threat_intel.shodan_client

Covers SDK-pattern adoption:
    - Rate limiting
    - Exception translation (ShodanAPIError)
    - count() for fast aggregates
    - search_cursor() pagination
    - bulk_lookup()
    - assess_finding_exposure() total_count wiring
"""
import time
from unittest.mock import MagicMock, patch, call

import pytest

from pipeline.threat_intel.shodan_client import (
    ShodanClient,
    ShodanAPIError,
    ShodanExposureResult,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_shodan_sdk():
    """Return a mocked shodan.Shodan instance."""
    mock = MagicMock()
    mock.info.return_value = {
        "plan": "developer",
        "query_credits": 100,
        "scan_credits": 16,
    }
    mock.host.return_value = {"ip_str": "1.2.3.4", "ports": [80, 443]}
    mock.count.return_value = {"total": 42}
    mock.search.return_value = {
        "total": 150,
        "matches": [
            {"ip_str": "1.2.3.4", "product": "nginx", "location": {"country_name": "US"}},
            {"ip_str": "5.6.7.8", "product": "apache", "location": {"country_name": "DE"}},
        ],
    }
    return mock


@pytest.fixture
def client(mock_shodan_sdk):
    """Return a ShodanClient backed by a mocked SDK."""
    with patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"}):
        with patch("shodan.Shodan") as MockShodan:
            MockShodan.return_value = mock_shodan_sdk
            c = ShodanClient()
            assert c.is_available()
            return c


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

def test_init_without_key():
    with patch.dict("os.environ", {}, clear=True):
        c = ShodanClient()
        assert not c.is_available()


def test_init_validates_key(mock_shodan_sdk):
    with patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"}):
        with patch("shodan.Shodan") as MockShodan:
            MockShodan.return_value = mock_shodan_sdk
            c = ShodanClient()
            assert c.is_available()
            assert c._api_info["plan"] == "developer"


def test_init_invalid_key_sets_unavailable(mock_shodan_sdk):
    """If info() raises, client should mark itself unavailable."""
    mock_shodan_sdk.info.side_effect = Exception("Invalid API key")
    with patch.dict("os.environ", {"SHODAN_API_KEY": "bad-key"}):
        with patch("shodan.Shodan") as MockShodan:
            MockShodan.return_value = mock_shodan_sdk
            c = ShodanClient()
            assert not c.is_available()


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def test_rate_limit_enforced(client, mock_shodan_sdk):
    client.api_rate_limit = 2  # 2 req/sec
    client._mark_query()

    t0 = time.time()
    client.lookup_host("1.2.3.4")
    t1 = time.time()

    # Should have waited at least 0.5s between calls
    assert t1 - t0 >= 0.4


def test_rate_limit_disabled_when_zero(client):
    client.api_rate_limit = 0
    client._mark_query()
    t0 = time.time()
    client._rate_limit()
    # Should return immediately
    assert time.time() - t0 < 0.05


# ---------------------------------------------------------------------------
# Exception translation
# ---------------------------------------------------------------------------

def test_wrap_api_call_raises_shodan_api_error(client):
    def boom():
        raise Exception("Some random failure")

    with pytest.raises(ShodanAPIError, match="Some random failure"):
        client._wrap_api_call(boom)


def test_wrap_api_call_translates_401(client):
    def boom():
        raise Exception("Invalid API key")
    with pytest.raises(ShodanAPIError, match="Invalid API key"):
        client._wrap_api_call(boom)


def test_wrap_api_call_translates_403(client):
    def boom():
        raise Exception("Access denied (403 Forbidden)")
    with pytest.raises(ShodanAPIError, match="Access denied"):
        client._wrap_api_call(boom)


def test_lookup_host_returns_none_on_error(client, mock_shodan_sdk):
    """lookup_host() should swallow ShodanAPIError and return None."""
    mock_shodan_sdk.host.side_effect = Exception("502 Bad Gateway")
    result = client.lookup_host("1.2.3.4")
    assert result is None


# ---------------------------------------------------------------------------
# count() — fast aggregate
# ---------------------------------------------------------------------------

def test_count_returns_total(client, mock_shodan_sdk):
    result = client.count("product:nginx")
    assert result["total"] == 42
    mock_shodan_sdk.count.assert_called_once_with("product:nginx", facets=None)


def test_count_with_facets(client, mock_shodan_sdk):
    client.count("product:nginx", facets=["country", "org"])
    mock_shodan_sdk.count.assert_called_once_with(
        "product:nginx", facets=["country", "org"]
    )


# ---------------------------------------------------------------------------
# search_cursor() — pagination
# ---------------------------------------------------------------------------

def test_search_cursor_yields_all_matches(client, mock_shodan_sdk):
    """Cursor should yield every match across multiple pages."""
    # Simulate 150 total results across 2 pages (100 per page)
    mock_shodan_sdk.search.side_effect = [
        {
            "total": 150,
            "matches": [{"ip_str": f"1.1.1.{i}"} for i in range(100)],
        },
        {
            "total": 150,
            "matches": [{"ip_str": f"2.2.2.{i}"} for i in range(50)],
        },
    ]

    banners = list(client.search_cursor("nginx"))
    assert len(banners) == 150
    assert banners[0]["ip_str"] == "1.1.1.0"
    assert banners[100]["ip_str"] == "2.2.2.0"


def test_search_cursor_empty_result(client, mock_shodan_sdk):
    mock_shodan_sdk.search.return_value = {"total": 0, "matches": []}
    banners = list(client.search_cursor("no-results"))
    assert banners == []


def test_search_cursor_retries_then_raises(client, mock_shodan_sdk):
    """After max_retries failures, cursor should raise ShodanAPIError."""
    mock_shodan_sdk.search.side_effect = [
        {"total": 200, "matches": [{"ip_str": "1.1.1.1"}]},  # page 1 OK
        Exception("timeout"),  # page 2 fails
        Exception("timeout"),  # page 2 retry 1
        Exception("timeout"),  # page 2 retry 2
        Exception("timeout"),  # page 2 retry 3
        Exception("timeout"),  # page 2 retry 4
        Exception("timeout"),  # page 2 retry 5
    ]

    gen = client.search_cursor("nginx")
    next(gen)  # consume page 1
    with pytest.raises(ShodanAPIError, match="Retry limit reached"):
        next(gen)


# ---------------------------------------------------------------------------
# bulk_lookup()
# ---------------------------------------------------------------------------

def test_bulk_lookup_multi_ip(client, mock_shodan_sdk):
    result = client.bulk_lookup(["1.2.3.4", "5.6.7.8"])
    mock_shodan_sdk.host.assert_called_once_with(["1.2.3.4", "5.6.7.8"])
    assert result == mock_shodan_sdk.host.return_value


def test_bulk_lookup_empty_list(client, mock_shodan_sdk):
    result = client.bulk_lookup([])
    assert result == {}
    mock_shodan_sdk.host.assert_not_called()


# ---------------------------------------------------------------------------
# assess_finding_exposure()
# ---------------------------------------------------------------------------

def test_assess_finding_uses_count_for_total(client, mock_shodan_sdk):
    """assess_finding_exposure() should call count() to get total_count."""
    mock_shodan_sdk.count.return_value = {"total": 9999}
    mock_shodan_sdk.search.return_value = {
        "total": 9999,
        "matches": [
            {"ip_str": "1.2.3.4", "product": "nginx", "location": {"country_name": "US"}, "org": "Acme"},
        ],
    }

    finding = {
        "id": "F-001",
        "cwe_id": "CVE-2021-44228",
        "bug_class": "format-string",  # no service mapping
        "location": "main.c:42",  # no service keyword to avoid double counting
    }
    result = client.assess_finding_exposure(finding)

    assert isinstance(result, ShodanExposureResult)
    assert result.internet_exposed is True
    assert result.total_count == 9999
    assert result.host_count == 1  # sample size
    assert result.exposure_score > 0
    assert result.countries == ["US"]


def test_assess_finding_with_service_name(client, mock_shodan_sdk):
    """Service name extracted from location should trigger product search."""
    mock_shodan_sdk.count.return_value = {"total": 100}
    mock_shodan_sdk.search.return_value = {"total": 100, "matches": []}

    finding = {
        "id": "F-002",
        "cwe_id": "",
        "bug_class": "sql-injection",
        "location": "mysql_connector.py:55",
    }
    result = client.assess_finding_exposure(finding)

    # count should have been called for both vuln and service queries
    assert mock_shodan_sdk.count.call_count == 1  # only service, no CVE
    call_args = mock_shodan_sdk.count.call_args_list[0]
    assert "product:mysql" in call_args[0][0]
    assert result.total_count == 100


def test_assess_finding_not_available():
    with patch.dict("os.environ", {}, clear=True):
        c = ShodanClient()
        result = c.assess_finding_exposure({"id": "F-003"})
        assert result.internet_exposed is False
        assert result.total_count == 0
        assert result.exposure_score == 0.0


# ---------------------------------------------------------------------------
# Exposure score calculation
# ---------------------------------------------------------------------------

def test_exposure_score_zero_hosts():
    """No hosts => score should be 0 (before multiplier)."""
    c = ShodanClient(api_key="dummy")
    score = c._calculate_exposure_score(0, 0, 0, 0, "buffer-overflow")
    assert score == 0.0


def test_exposure_score_with_hosts():
    c = ShodanClient(api_key="dummy")
    score = c._calculate_exposure_score(100, 3, 5, 2, "buffer-overflow")
    assert score > 0
    assert score <= 100.0


def test_exposure_score_multiplier():
    """Buffer-overflow should get a 1.3x multiplier."""
    c = ShodanClient(api_key="dummy")
    base_score = c._calculate_exposure_score(10, 1, 1, 0, "generic")
    overflow_score = c._calculate_exposure_score(10, 1, 1, 0, "buffer-overflow")
    assert overflow_score > base_score


# ---------------------------------------------------------------------------
# _extract_service_name()
# ---------------------------------------------------------------------------

def test_extract_service_from_location():
    c = ShodanClient(api_key="dummy")
    assert c._extract_service_name("/etc/nginx/nginx.conf", "") == "nginx"
    assert c._extract_service_name("src/redis_client.py", "") == "redis"
    assert c._extract_service_name("unknown_module.go", "") is None


def test_extract_service_from_bug_class():
    c = ShodanClient(api_key="dummy")
    assert c._extract_service_name("app.py", "sql-injection") == "mysql"
    assert c._extract_service_name("app.py", "xss") == "nginx"


# ---------------------------------------------------------------------------
# Empty result
# ---------------------------------------------------------------------------

def test_empty_result_has_total_count():
    c = ShodanClient(api_key="dummy")
    result = c._empty_result("F-000")
    assert result.total_count == 0
    assert result.internet_exposed is False
