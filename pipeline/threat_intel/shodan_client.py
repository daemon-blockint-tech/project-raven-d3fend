"""
Shodan Integration for External Exposure Scoring

Integrates the Shodan search engine to discover internet-facing assets
and assess external exposure of vulnerabilities found by Raven.

Patterns adopted from the official shodan-python SDK (v1.31.0):
    - requests.Session reuse for connection pooling
    - Rate-limit guard to respect API limits (1 req/sec by default)
    - count() for fast aggregate exposure scale without full enumeration
    - search_cursor() generator for auto-pagination
    - Proper APIError hierarchy for upstream exception handling
    - info() key validation on init
    - Bulk host() lookups (multi-IP)

Usage:
    client = ShodanClient(api_key=os.getenv("SHODAN_API_KEY"))
    exposure = client.assess_finding_exposure(finding)
"""
import logging
import math
import os
import time
from dataclasses import dataclass
from typing import Dict, Generator, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class ShodanAPIError(Exception):
    """Raised when the Shodan API returns a non-200 status or an error response."""
    def __init__(self, value: str):
        self.value = value

    def __str__(self) -> str:
        return self.value


@dataclass
class ShodanExposureResult:
    """Result of Shodan exposure assessment for a finding."""
    finding_id: str
    internet_exposed: bool
    host_count: int
    total_count: int  # Full count via count(), not just returned matches
    exposed_services: List[str]
    countries: List[str]
    orgs: List[str]
    last_seen: Optional[str]
    tags: List[str]
    vulns_matched: List[str]
    exposure_score: float  # 0-100, derived from Shodan data
    raw_matches: List[Dict[str, Any]]


class ShodanClient:
    """
    Shodan API client for Raven's threat intelligence layer.

    Provides:
    - Host lookup by IP/domain (single and bulk)
    - Service / CVE search for exposed vulnerabilities
    - count() for fast aggregate exposure scale
    - search_cursor() generator for paginated enumeration
    - Exposure scoring based on internet-facing assets
    - Rate-limited, session-pooled API calls
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("SHODAN_API_KEY")
        self._shodan = None
        self._available = False
        self._api_info: Optional[Dict[str, Any]] = None
        self.api_rate_limit = 1  # Requests per second (configurable)
        self._api_query_time: Optional[float] = None

        if self.api_key:
            try:
                import shodan
                self._shodan = shodan.Shodan(self.api_key)
                self._available = True
                # Validate key and surface plan info
                try:
                    self._api_info = self.info()
                    plan = self._api_info.get("plan", "unknown")
                    query_credits = self._api_info.get("query_credits", 0)
                    logger.info(
                        "Shodan client initialized: plan=%s, query_credits=%s",
                        plan,
                        query_credits,
                    )
                except ShodanAPIError as exc:
                    logger.warning("Shodan key validation failed: %s", exc)
                    self._available = False
            except ImportError:
                logger.warning(
                    "shodan package not installed. "
                    "Install with: pip install shodan"
                )
            except Exception as exc:
                logger.error("Shodan init failed: %s", exc)
        else:
            logger.warning(
                "SHODAN_API_KEY not set. Shodan integration disabled."
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _rate_limit(self) -> None:
        """Respect Shodan's API rate limit (default 1 req/sec)."""
        if self._api_query_time is not None and self.api_rate_limit > 0:
            min_interval = 1.0 / self.api_rate_limit
            while min_interval + self._api_query_time >= time.time():
                time.sleep(0.1 / self.api_rate_limit)

    def _mark_query(self) -> None:
        """Record the time of the last API query for rate-limit tracking."""
        self._api_query_time = time.time()

    def _wrap_api_call(self, fn, *args, **kwargs):
        """Execute a Shodan SDK call with rate limiting and ShodanAPIError translation."""
        if not self.is_available():
            raise ShodanAPIError("Shodan client is not available")
        self._rate_limit()
        try:
            result = fn(*args, **kwargs)
            self._mark_query()
            return result
        except Exception as exc:
            # Translate known SDK exception types
            msg = str(exc)
            if "Invalid API key" in msg or "401" in msg:
                raise ShodanAPIError(f"Invalid API key: {msg}")
            if "Access denied" in msg or "403" in msg:
                raise ShodanAPIError(f"Access denied: {msg}")
            if "Bad Gateway" in msg or "502" in msg:
                raise ShodanAPIError(f"Shodan service unavailable: {msg}")
            raise ShodanAPIError(msg)

    # ------------------------------------------------------------------
    # Public API (mirrors official SDK where useful)
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Check if Shodan API is available and initialized."""
        return self._available and self._shodan is not None

    def info(self) -> Dict[str, Any]:
        """
        Return API-key metadata: plan, query_credits, scan_credits, etc.
        Raises ShodanAPIError on failure.
        """
        return self._wrap_api_call(self._shodan.info)

    def lookup_host(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Look up a single host by IP address.

        Args:
            ip: IP address to look up

        Returns:
            Host data dict or None if unavailable/error
        """
        try:
            return self._wrap_api_call(self._shodan.host, ip)
        except ShodanAPIError as exc:
            logger.warning("Shodan host lookup failed for %s: %s", ip, exc)
            return None

    def bulk_lookup(self, ips: List[str]) -> Dict[str, Any]:
        """
        Look up multiple hosts in a single API call.

        Args:
            ips: List of IP addresses

        Returns:
            Host data dict (contains multiple hosts under the 'data' key)
        """
        if not ips:
            return {}
        try:
            return self._wrap_api_call(self._shodan.host, ips)
        except ShodanAPIError as exc:
            logger.warning("Shodan bulk lookup failed for %s: %s", ips, exc)
            return {}

    def count(self, query: str, facets: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Fast aggregate query: returns total result count + optional facet breakdown.

        Args:
            query: Shodan search query
            facets: Optional list of properties for summary aggregation

        Returns:
            Dict with 'total' and optional 'facets'
        """
        return self._wrap_api_call(self._shodan.count, query, facets=facets)

    def search(
        self,
        query: str,
        limit: Optional[int] = None,
        facets: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Search the Shodan database.

        Args:
            query: Shodan search query
            limit: Maximum results to return (defaults to SDK default)
            facets: Optional list of properties for summary aggregation

        Returns:
            Dict with 'matches', 'total', and optional 'facets'
        """
        kwargs: Dict[str, Any] = {}
        if limit is not None:
            kwargs["limit"] = limit
        if facets is not None:
            kwargs["facets"] = facets
        return self._wrap_api_call(self._shodan.search, query, **kwargs)

    def search_cursor(
        self,
        query: str,
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Generator that auto-pages through all results for a query.

        Yields each banner/match dict individually.  Use this when you
        need to enumerate the full result set without manually handling
        pagination.

        Args:
            query: Shodan search query

        Yields:
            Individual match dictionaries
        """
        if not self.is_available():
            return

        page = 1
        total_pages = 0
        tries = 0
        max_retries = 5

        try:
            self._rate_limit()
            results = self._shodan.search(query, page=page)
            self._mark_query()
        except Exception as exc:
            logger.warning("Shodan search_cursor initial page failed: %s", exc)
            return

        if results.get("total"):
            total_pages = int(math.ceil(results["total"] / 100))

        for banner in results.get("matches", []):
            yield banner

        page += 1

        while page <= total_pages:
            try:
                self._rate_limit()
                results = self._shodan.search(query, page=page)
                self._mark_query()
                for banner in results.get("matches", []):
                    yield banner
                page += 1
                tries = 0
            except Exception as exc:
                if tries >= max_retries:
                    logger.warning(
                        "Shodan search_cursor retry limit reached (%d): %s",
                        max_retries,
                        exc,
                    )
                    raise ShodanAPIError(
                        f"Retry limit reached ({max_retries}): {exc}"
                    )
                tries += 1
                time.sleep(tries)

    def search_vulnerability(
        self,
        cve_id: str,
        port: Optional[int] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Search Shodan for hosts vulnerable to a specific CVE.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")
            port: Optional port filter
            limit: Maximum results to return

        Returns:
            List of matching host data dicts
        """
        if not self.is_available():
            return []

        query = f"vuln:{cve_id}"
        if port:
            query += f" port:{port}"

        try:
            results = self.search(query, limit=limit)
            return list(results.get("matches", []))
        except ShodanAPIError as exc:
            logger.warning("Shodan search failed for %s: %s", cve_id, exc)
            return []

    def search_service(
        self,
        service_name: str,
        version: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Search for exposed services (e.g., "apache", "nginx", "mongodb").

        Args:
            service_name: Service/product name
            version: Optional version string
            limit: Maximum results

        Returns:
            List of matching host data dicts
        """
        if not self.is_available():
            return []

        query = f"product:{service_name}"
        if version:
            query += f" version:{version}"

        try:
            results = self.search(query, limit=limit)
            return list(results.get("matches", []))
        except ShodanAPIError as exc:
            logger.warning("Shodan search failed for %s: %s", service_name, exc)
            return []

    # ------------------------------------------------------------------
    # Raven-specific exposure assessment
    # ------------------------------------------------------------------

    def assess_finding_exposure(
        self,
        finding: Dict[str, Any],
        search_vulns: bool = True,
        search_services: bool = True,
    ) -> ShodanExposureResult:
        """
        Assess the external exposure of a finding using Shodan.

        Uses count() for fast aggregate scale checks, then enumerates
        a sample of matches for metadata (services, countries, orgs).

        Args:
            finding: Finding dict with at minimum:
                - id: str
                - cwe_id: Optional[str]
                - bug_class: str
                - location: str (may contain service name)
            search_vulns: Whether to search by CVE
            search_services: Whether to search by service name

        Returns:
            ShodanExposureResult with exposure score and metadata
        """
        if not self.is_available():
            return self._empty_result(finding.get("id", "unknown"))

        finding_id = finding.get("id", "unknown")
        cve_id = finding.get("cwe_id", "")
        bug_class = finding.get("bug_class", "")
        location = finding.get("location", "")

        all_matches: List[Dict[str, Any]] = []
        exposed_services: set = set()
        countries: set = set()
        orgs: set = set()
        tags: set = set()
        vulns: set = set()
        total_count = 0

        # Helper to collect metadata from a list of matches
        def _collect(matches: List[Dict[str, Any]]) -> None:
            for m in matches:
                if "product" in m:
                    exposed_services.add(m["product"])
                loc = m.get("location", {})
                if isinstance(loc, dict) and "country_name" in loc:
                    countries.add(loc["country_name"])
                if "org" in m:
                    orgs.add(m["org"])
                if "tags" in m:
                    tags.update(m["tags"])
                if "vulns" in m:
                    vulns.update(m["vulns"])

        # Search by CVE if available
        if search_vulns and cve_id and cve_id.startswith("CVE-"):
            query = f"vuln:{cve_id}"
            try:
                count_result = self.count(query)
                total_count += count_result.get("total", 0)
            except ShodanAPIError as exc:
                logger.debug("Shodan count failed for %s: %s", cve_id, exc)

            cve_matches = self.search_vulnerability(cve_id, limit=20)
            all_matches.extend(cve_matches)
            _collect(cve_matches)

        # Search by service name extracted from location
        if search_services and location:
            service_name = self._extract_service_name(location, bug_class)
            if service_name:
                query = f"product:{service_name}"
                try:
                    count_result = self.count(query)
                    total_count += count_result.get("total", 0)
                except ShodanAPIError as exc:
                    logger.debug("Shodan count failed for %s: %s", service_name, exc)

                svc_matches = self.search_service(service_name, limit=20)
                all_matches.extend(svc_matches)
                _collect(svc_matches)

        # Calculate exposure score using total_count (not just sample size)
        exposure_score = self._calculate_exposure_score(
            total_count,
            len(exposed_services),
            len(countries),
            len(vulns),
            bug_class,
        )

        return ShodanExposureResult(
            finding_id=finding_id,
            internet_exposed=total_count > 0,
            host_count=len(all_matches),
            total_count=total_count,
            exposed_services=sorted(list(exposed_services)),
            countries=sorted(list(countries)),
            orgs=sorted(list(orgs)),
            last_seen=datetime.utcnow().isoformat(),
            tags=sorted(list(tags)),
            vulns_matched=sorted(list(vulns)),
            exposure_score=exposure_score,
            raw_matches=all_matches[:10],  # Limit raw data
        )

    def _extract_service_name(self, location: str, bug_class: str) -> Optional[str]:
        """Extract a searchable service name from finding location."""
        # Common service patterns
        service_patterns = {
            "apache": "apache",
            "nginx": "nginx",
            "tomcat": "tomcat",
            "iis": "iis",
            "mongodb": "mongodb",
            "mysql": "mysql",
            "postgresql": "postgresql",
            "redis": "redis",
            "elasticsearch": "elasticsearch",
            "docker": "docker",
            "kubernetes": "kubernetes",
            "ssh": "ssh",
            "telnet": "telnet",
            "ftp": "ftp",
            "smtp": "smtp",
            "vpn": "vpn",
            "rdp": "rdp",
            "vnc": "vnc",
            "jenkins": "jenkins",
            "gitlab": "gitlab",
            "grafana": "grafana",
            "prometheus": "prometheus",
        }

        location_lower = location.lower()
        for keyword, service in service_patterns.items():
            if keyword in location_lower:
                return service

        # Bug class hints
        bug_class_services = {
            "sql-injection": "mysql",
            "xss": "nginx",
            "command-injection": "ssh",
            "path-traversal": "nginx",
            "buffer-overflow": "apache",
        }

        return bug_class_services.get(bug_class.lower())

    def _calculate_exposure_score(
        self,
        host_count: int,
        service_count: int,
        country_count: int,
        vuln_count: int,
        bug_class: str
    ) -> float:
        """
        Calculate an exposure score from 0-100 based on Shodan data.

        Higher score = more exposed = more critical.
        """
        score = 0.0

        # Host count (0-40 points)
        if host_count > 0:
            score += min(40, 10 + host_count * 0.5)

        # Service diversity (0-20 points)
        score += min(20, service_count * 5)

        # Geographic spread (0-20 points)
        score += min(20, country_count * 4)

        # Known vulnerabilities (0-20 points)
        score += min(20, vuln_count * 2)

        # Bug class multiplier
        multipliers = {
            "buffer-overflow": 1.3,
            "use-after-free": 1.2,
            "race-condition": 1.1,
            "auth-bypass": 1.4,
            "integer-overflow": 1.2,
            "reentrancy": 1.3,
            "oracle-manipulation": 1.2,
        }
        multiplier = multipliers.get(bug_class.lower(), 1.0)
        score *= multiplier

        return min(100.0, score)

    def _empty_result(self, finding_id: str) -> ShodanExposureResult:
        """Return an empty result when Shodan is unavailable."""
        return ShodanExposureResult(
            finding_id=finding_id,
            internet_exposed=False,
            host_count=0,
            total_count=0,
            exposed_services=[],
            countries=[],
            orgs=[],
            last_seen=None,
            tags=[],
            vulns_matched=[],
            exposure_score=0.0,
            raw_matches=[]
        )
