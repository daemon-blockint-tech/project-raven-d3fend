"""
Shodan Integration for External Exposure Scoring

Integrates the Shodan search engine to discover internet-facing assets
and assess external exposure of vulnerabilities found by Raven.

Usage:
    client = ShodanClient(api_key=os.getenv("SHODAN_API_KEY"))
    exposure = client.assess_finding_exposure(finding)
"""
import logging
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class ShodanExposureResult:
    """Result of Shodan exposure assessment for a finding."""
    finding_id: str
    internet_exposed: bool
    host_count: int
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
    - Host lookup by IP/domain
    - Service search for exposed vulnerabilities
    - Exposure scoring based on internet-facing assets
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("SHODAN_API_KEY")
        self._shodan = None
        self._available = False

        if self.api_key:
            try:
                import shodan
                self._shodan = shodan.Shodan(self.api_key)
                self._available = True
                logger.info("Shodan client initialized")
            except ImportError:
                logger.warning(
                    "shodan package not installed. "
                    "Install with: pip install shodan"
                )
            except Exception as e:
                logger.error(f"Shodan init failed: {e}")
        else:
            logger.warning(
                "SHODAN_API_KEY not set. Shodan integration disabled."
            )

    def is_available(self) -> bool:
        """Check if Shodan API is available and initialized."""
        return self._available and self._shodan is not None

    def lookup_host(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Look up a single host by IP address.

        Args:
            ip: IP address to look up

        Returns:
            Host data dict or None if unavailable/error
        """
        if not self.is_available():
            return None

        try:
            return self._shodan.host(ip)
        except Exception as e:
            logger.warning(f"Shodan host lookup failed for {ip}: {e}")
            return None

    def search_vulnerability(
        self,
        cve_id: str,
        port: Optional[int] = None,
        limit: int = 100
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
            results = self._shodan.search(query, limit=limit)
            return list(results.get("matches", []))
        except Exception as e:
            logger.warning(f"Shodan search failed for {cve_id}: {e}")
            return []

    def search_service(
        self,
        service_name: str,
        version: Optional[str] = None,
        limit: int = 100
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
            results = self._shodan.search(query, limit=limit)
            return list(results.get("matches", []))
        except Exception as e:
            logger.warning(f"Shodan search failed for {service_name}: {e}")
            return []

    def assess_finding_exposure(
        self,
        finding: Dict[str, Any],
        search_vulns: bool = True,
        search_services: bool = True
    ) -> ShodanExposureResult:
        """
        Assess the external exposure of a finding using Shodan.

        Combines vulnerability search and service search to determine
        how exposed the finding is on the public internet.

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

        all_matches = []
        exposed_services = set()
        countries = set()
        orgs = set()
        tags = set()
        vulns = set()

        # Search by CVE if available
        if search_vulns and cve_id and cve_id.startswith("CVE-"):
            cve_matches = self.search_vulnerability(cve_id, limit=50)
            for m in cve_matches:
                all_matches.append(m)
                if "product" in m:
                    exposed_services.add(m["product"])
                if "location" in m and "country_name" in m["location"]:
                    countries.add(m["location"]["country_name"])
                if "org" in m:
                    orgs.add(m["org"])
                if "tags" in m:
                    tags.update(m["tags"])
                if "vulns" in m:
                    vulns.update(m["vulns"])

        # Search by service name extracted from location
        if search_services and location:
            service_name = self._extract_service_name(location, bug_class)
            if service_name:
                svc_matches = self.search_service(service_name, limit=50)
                for m in svc_matches:
                    all_matches.append(m)
                    if "product" in m:
                        exposed_services.add(m["product"])
                    if "location" in m and "country_name" in m["location"]:
                        countries.add(m["location"]["country_name"])
                    if "org" in m:
                        orgs.add(m["org"])

        # Calculate exposure score
        exposure_score = self._calculate_exposure_score(
            len(all_matches),
            len(exposed_services),
            len(countries),
            len(vulns),
            bug_class
        )

        return ShodanExposureResult(
            finding_id=finding_id,
            internet_exposed=len(all_matches) > 0,
            host_count=len(all_matches),
            exposed_services=sorted(list(exposed_services)),
            countries=sorted(list(countries)),
            orgs=sorted(list(orgs)),
            last_seen=datetime.now().isoformat(),
            tags=sorted(list(tags)),
            vulns_matched=sorted(list(vulns)),
            exposure_score=exposure_score,
            raw_matches=all_matches[:10]  # Limit raw data
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
            exposed_services=[],
            countries=[],
            orgs=[],
            last_seen=None,
            tags=[],
            vulns_matched=[],
            exposure_score=0.0,
            raw_matches=[]
        )
