"""
DNSWatch Data Models

Pydantic models for DNS query data, analysis results, and threat detection.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


class QueryType(str, Enum):
    """DNS query types"""
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    SOA = "SOA"
    PTR = "PTR"
    SRV = "SRV"
    DNSKEY = "DNSKEY"
    DS = "DS"
    RRSIG = "RRSIG"
    ANY = "ANY"
    OTHER = "OTHER"


class ThreatLevel(str, Enum):
    """Threat severity levels"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(str, Enum):
    """Types of DNS threats"""
    MALWARE = "malware"
    PHISHING = "phishing"
    DGA = "dga"  # Domain Generation Algorithm
    TYPOSQUATTING = "typosquatting"
    FAST_FLUX = "fast_flux"
    DNS_TUNNELING = "dns_tunneling"
    SUSPICIOUS_TLD = "suspicious_tld"
    NEW_DOMAIN = "new_domain"
    LONG_DOMAIN = "long_domain"
    HIGH_ENTROPY = "high_entropy"
    NONE = "none"


@dataclass
class DNSRecord:
    """DNS record information"""
    name: str
    record_type: QueryType
    ttl: int
    value: str
    priority: Optional[int] = None


@dataclass
class DNSQuery:
    """DNS query record"""
    timestamp: datetime
    domain: str
    query_type: QueryType
    nameserver: str
    response_time_ms: float
    records: List[DNSRecord] = field(default_factory=list)
    error: Optional[str] = None
    source_ip: Optional[str] = None
    response_code: str = "NOERROR"
    
    @property
    def is_successful(self) -> bool:
        """Check if query was successful"""
        return self.error is None and self.response_code == "NOERROR"
    
    @property
    def domain_parts(self) -> List[str]:
        """Split domain into parts"""
        return self.domain.rstrip(".").split(".")
    
    @property
    def tld(self) -> str:
        """Get top-level domain"""
        parts = self.domain_parts
        return parts[-1] if parts else ""
    
    @property
    def subdomain(self) -> str:
        """Get subdomain (everything before the main domain)"""
        parts = self.domain_parts
        if len(parts) <= 2:
            return ""
        return ".".join(parts[:-2])


@dataclass
class ThreatIndicator:
    """Threat detection indicator"""
    threat_type: ThreatType
    level: ThreatLevel
    description: str
    score: float  # 0.0 to 1.0
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DNSAnalysisResult:
    """DNS query analysis result"""
    query: DNSQuery
    threats: List[ThreatIndicator] = field(default_factory=list)
    performance_score: float = 1.0  # 0.0 to 1.0
    is_suspicious: bool = False
    recommendations: List[str] = field(default_factory=list)
    
    @property
    def max_threat_level(self) -> ThreatLevel:
        """Get the highest threat level"""
        if not self.threats:
            return ThreatLevel.SAFE
        
        level_order = {
            ThreatLevel.SAFE: 0,
            ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.HIGH: 3,
            ThreatLevel.CRITICAL: 4
        }
        
        max_level = ThreatLevel.SAFE
        for threat in self.threats:
            if level_order[threat.level] > level_order[max_level]:
                max_level = threat.level
        
        return max_level
    
    @property
    def total_threat_score(self) -> float:
        """Calculate total threat score"""
        if not self.threats:
            return 0.0
        return min(1.0, sum(t.score for t in self.threats))


@dataclass
class DNSStatistics:
    """DNS query statistics"""
    total_queries: int = 0
    successful_queries: int = 0
    failed_queries: int = 0
    avg_response_time_ms: float = 0.0
    min_response_time_ms: float = float("inf")
    max_response_time_ms: float = 0.0
    
    # Query type distribution
    query_types: Dict[str, int] = field(default_factory=dict)
    
    # Top domains
    top_domains: List[tuple] = field(default_factory=list)
    
    # Threat statistics
    safe_queries: int = 0
    suspicious_queries: int = 0
    threat_breakdown: Dict[str, int] = field(default_factory=dict)
    
    # TLD distribution
    tld_distribution: Dict[str, int] = field(default_factory=dict)
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate"""
        if self.total_queries == 0:
            return 0.0
        return self.successful_queries / self.total_queries
    
    @property
    def suspicious_rate(self) -> float:
        """Calculate suspicious query rate"""
        if self.total_queries == 0:
            return 0.0
        return self.suspicious_queries / self.total_queries


@dataclass
class MonitoringSession:
    """DNS monitoring session"""
    session_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    queries: List[DNSQuery] = field(default_factory=list)
    analysis_results: List[DNSAnalysisResult] = field(default_factory=list)
    statistics: DNSStatistics = field(default_factory=DNSStatistics)
    config: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration_seconds(self) -> float:
        """Calculate session duration in seconds"""
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()
    
    @property
    def queries_per_second(self) -> float:
        """Calculate queries per second"""
        duration = self.duration_seconds
        if duration == 0:
            return 0.0
        return len(self.queries) / duration


def parse_domain(domain: str) -> Dict[str, Any]:
    """
    Parse domain and extract useful information.
    
    Args:
        domain: Domain name to parse
        
    Returns:
        Dictionary with parsed domain information
    """
    domain = domain.rstrip(".").lower()
    parts = domain.split(".")
    
    result = {
        "full_domain": domain,
        "parts": parts,
        "part_count": len(parts),
        "tld": parts[-1] if parts else "",
        "domain": ".".join(parts[-2:]) if len(parts) >= 2 else domain,
        "subdomain": ".".join(parts[:-2]) if len(parts) > 2 else "",
        "length": len(domain),
        "has_www": parts[0] == "www" if parts else False,
        "is_ip": all(c.isdigit() or c == "." for c in domain) if domain else False
    }
    
    # Calculate entropy
    if domain:
        from collections import Counter
        import math
        counter = Counter(domain)
        length = len(domain)
        result["entropy"] = -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
        )
    else:
        result["entropy"] = 0.0
    
    return result


def is_valid_domain(domain: str) -> bool:
    """
    Check if a domain name is valid.
    
    Args:
        domain: Domain name to validate
        
    Returns:
        True if domain is valid
    """
    if not domain or len(domain) > 253:
        return False
    
    # Remove trailing dot
    domain = domain.rstrip(".")
    
    # Check for valid characters
    allowed_chars = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
    if not all(c in allowed_chars for c in domain.lower()):
        return False
    
    # Check each label
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    
    return True
