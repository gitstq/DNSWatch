"""
DNS Threat Detector Module

Detects suspicious DNS activity including malware domains,
phishing, DGA domains, DNS tunneling, and other threats.
"""

import hashlib
import math
import re
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from dnswatch.models import (
    DNSAnalysisResult,
    DNSQuery,
    ThreatIndicator,
    ThreatLevel,
    ThreatType,
    parse_domain,
)


class ThreatDetector:
    """
    DNS Threat Detection Engine
    
    Analyzes DNS queries for potential security threats using
    heuristic rules, pattern matching, and statistical analysis.
    """
    
    # Suspicious TLDs often associated with malware
    SUSPICIOUS_TLDS = {
        "tk", "ml", "ga", "cf", "gq",  # Free TLDs
        "xyz", "top", "pw", "cc", "work",
        "click", "link", "info", "biz",
        "online", "site", "club", "win",
    }
    
    # Known malicious domain patterns
    MALICIOUS_PATTERNS = [
        r"paypal.*verify",
        r"amazon.*secure",
        r"bank.*confirm",
        r"account.*suspend",
        r"password.*reset",
        r"login.*secure",
        r"update.*payment",
        r"verify.*identity",
    ]
    
    # Common typosquatting patterns
    TYPOSQUATTING_PATTERNS = [
        (r"g[o0]{0,1}[o0]{0,1}gle", "google"),
        (r"faceb[o0]{0,1}[o0]{0,1}k", "facebook"),
        (r"amaz[o0]{0,1}n", "amazon"),
        (r"micr[o0]{0,1}s[o0]{0,1}ft", "microsoft"),
        (r"apple", "apple"),
        (r"tw[i1]tter", "twitter"),
        (r"[1l]inked[1l]n", "linkedin"),
    ]
    
    # Popular domains for typosquatting detection
    POPULAR_DOMAINS = {
        "google.com", "facebook.com", "amazon.com", "microsoft.com",
        "apple.com", "twitter.com", "linkedin.com", "github.com",
        "youtube.com", "netflix.com", "instagram.com", "whatsapp.com",
        "paypal.com", "ebay.com", "yahoo.com", "live.com",
        "outlook.com", "office.com", "bing.com", "msn.com",
    }
    
    # DNS tunneling indicators
    TUNNELING_INDICATORS = [
        r"^[a-z0-9]{20,}$",  # Long random subdomain
        r"^[a-z0-9]+\.[a-z0-9]+\.[a-z0-9]+\.[a-z0-9]+",  # Multiple numeric segments
    ]
    
    # Base64-like patterns (common in DNS tunneling)
    BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")
    
    # Hex-encoded data pattern
    HEX_PATTERN = re.compile(r"^[0-9a-fA-F]{16,}$")
    
    def __init__(
        self,
        enable_dga_detection: bool = True,
        enable_typosquatting: bool = True,
        enable_tunneling: bool = True,
        entropy_threshold: float = 3.5,
        min_domain_length: int = 10,
    ):
        """
        Initialize Threat Detector.
        
        Args:
            enable_dga_detection: Enable DGA domain detection
            enable_typosquatting: Enable typosquatting detection
            enable_tunneling: Enable DNS tunneling detection
            entropy_threshold: Entropy threshold for DGA detection
            min_domain_length: Minimum length for suspicious domain
        """
        self.enable_dga_detection = enable_dga_detection
        self.enable_typosquatting = enable_typosquatting
        self.enable_tunneling = enable_tunneling
        self.entropy_threshold = entropy_threshold
        self.min_domain_length = min_domain_length
        
        # Custom threat rules
        self._custom_rules: List[Dict[str, Any]] = []
        
        # Domain allowlist
        self._allowlist: Set[str] = set()
        
        # Domain blocklist
        self._blocklist: Set[str] = set()
    
    def add_custom_rule(
        self,
        name: str,
        pattern: str,
        threat_type: ThreatType,
        level: ThreatLevel,
        description: str,
    ) -> None:
        """Add custom threat detection rule"""
        self._custom_rules.append({
            "name": name,
            "pattern": re.compile(pattern, re.IGNORECASE),
            "threat_type": threat_type,
            "level": level,
            "description": description,
        })
    
    def add_to_allowlist(self, domain: str) -> None:
        """Add domain to allowlist"""
        self._allowlist.add(domain.lower())
    
    def add_to_blocklist(self, domain: str) -> None:
        """Add domain to blocklist"""
        self._blocklist.add(domain.lower())
    
    def analyze(self, query: DNSQuery) -> DNSAnalysisResult:
        """
        Analyze a DNS query for threats.
        
        Args:
            query: DNS query to analyze
            
        Returns:
            DNSAnalysisResult with threat indicators
        """
        result = DNSAnalysisResult(query=query)
        
        # Skip if domain is in allowlist
        if query.domain.lower() in self._allowlist:
            return result
        
        # Check blocklist first
        if query.domain.lower() in self._blocklist:
            result.threats.append(ThreatIndicator(
                threat_type=ThreatType.MALWARE,
                level=ThreatLevel.CRITICAL,
                description=f"Domain {query.domain} is in blocklist",
                score=1.0,
                details={"source": "blocklist"},
            ))
            result.is_suspicious = True
            return result
        
        # Parse domain information
        domain_info = parse_domain(query.domain)
        
        # Run all detection methods
        threats = []
        
        # Check suspicious TLD
        threats.extend(self._check_suspicious_tld(domain_info))
        
        # Check for typosquatting
        if self.enable_typosquatting:
            threats.extend(self._check_typosquatting(domain_info))
        
        # Check for DGA (Domain Generation Algorithm)
        if self.enable_dga_detection:
            threats.extend(self._check_dga(domain_info))
        
        # Check for DNS tunneling
        if self.enable_tunneling:
            threats.extend(self._check_tunneling(domain_info))
        
        # Check malicious patterns
        threats.extend(self._check_malicious_patterns(domain_info))
        
        # Check custom rules
        threats.extend(self._check_custom_rules(domain_info))
        
        # Check domain length
        threats.extend(self._check_domain_length(domain_info))
        
        # Calculate performance score
        result.performance_score = self._calculate_performance_score(query)
        
        # Add threats to result
        result.threats = threats
        result.is_suspicious = any(
            t.level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)
            for t in threats
        )
        
        # Generate recommendations
        result.recommendations = self._generate_recommendations(result)
        
        return result
    
    def _check_suspicious_tld(self, domain_info: Dict[str, Any]) -> List[ThreatIndicator]:
        """Check for suspicious TLD"""
        threats = []
        tld = domain_info.get("tld", "").lower()
        
        if tld in self.SUSPICIOUS_TLDS:
            threats.append(ThreatIndicator(
                threat_type=ThreatType.SUSPICIOUS_TLD,
                level=ThreatLevel.LOW,
                description=f"Domain uses suspicious TLD: .{tld}",
                score=0.3,
                details={"tld": tld},
            ))
        
        return threats
    
    def _check_typosquatting(self, domain_info: Dict[str, Any]) -> List[ThreatIndicator]:
        """Check for typosquatting domains"""
        threats = []
        domain = domain_info.get("domain", "").lower()
        full_domain = domain_info.get("full_domain", "").lower()
        
        # Check against popular domains
        for popular in self.POPULAR_DOMAINS:
            popular_base = popular.split(".")[0]
            domain_base = domain.split(".")[0] if "." in domain else domain
            
            # Check for common typosquatting techniques
            if self._is_typosquatting_match(domain_base, popular_base):
                threats.append(ThreatIndicator(
                    threat_type=ThreatType.TYPOSQUATTING,
                    level=ThreatLevel.MEDIUM,
                    description=f"Possible typosquatting of {popular}",
                    score=0.6,
                    details={
                        "target_domain": popular,
                        "technique": "character_substitution",
                    },
                ))
                break
        
        return threats
    
    def _is_typosquatting_match(self, domain: str, target: str) -> bool:
        """Check if domain is a typosquatting variant of target"""
        if domain == target:
            return False
        
        # Check for character substitution
        if len(domain) == len(target):
            diff_count = sum(1 for a, b in zip(domain, target) if a != b)
            if diff_count <= 2:
                return True
        
        # Check for character omission
        if len(domain) == len(target) - 1:
            for i in range(len(target)):
                if domain == target[:i] + target[i+1:]:
                    return True
        
        # Check for character addition
        if len(domain) == len(target) + 1:
            for i in range(len(domain)):
                if target == domain[:i] + domain[i+1:]:
                    return True
        
        # Check for character transposition
        if len(domain) == len(target):
            for i in range(len(domain) - 1):
                swapped = domain[:i] + domain[i+1] + domain[i] + domain[i+2:]
                if swapped == target:
                    return True
        
        return False
    
    def _check_dga(self, domain_info: Dict[str, Any]) -> List[ThreatIndicator]:
        """Check for DGA (Domain Generation Algorithm) indicators"""
        threats = []
        subdomain = domain_info.get("subdomain", "")
        entropy = domain_info.get("entropy", 0)
        length = domain_info.get("length", 0)
        
        # High entropy subdomain (common in DGA)
        if subdomain:
            sub_entropy = self._calculate_entropy(subdomain)
            if sub_entropy > self.entropy_threshold:
                threats.append(ThreatIndicator(
                    threat_type=ThreatType.DGA,
                    level=ThreatLevel.MEDIUM,
                    description="High entropy subdomain detected (possible DGA)",
                    score=0.5,
                    details={
                        "entropy": sub_entropy,
                        "threshold": self.entropy_threshold,
                    },
                ))
        
        # Check for random-looking domain
        if length >= self.min_domain_length and entropy > self.entropy_threshold:
            # Check for consonant/vowel ratio (DGA domains often have unusual ratios)
            domain = domain_info.get("full_domain", "")
            cv_ratio = self._calculate_consonant_vowel_ratio(domain)
            
            if cv_ratio > 5.0 or cv_ratio < 0.2:
                threats.append(ThreatIndicator(
                    threat_type=ThreatType.DGA,
                    level=ThreatLevel.MEDIUM,
                    description="Unusual character distribution (possible DGA)",
                    score=0.4,
                    details={
                        "entropy": entropy,
                        "cv_ratio": cv_ratio,
                    },
                ))
        
        return threats
    
    def _check_tunneling(self, domain_info: Dict[str, Any]) -> List[ThreatIndicator]:
        """Check for DNS tunneling indicators"""
        threats = []
        subdomain = domain_info.get("subdomain", "")
        
        if not subdomain:
            return threats
        
        # Check for base64-like encoding
        if self.BASE64_PATTERN.match(subdomain):
            threats.append(ThreatIndicator(
                threat_type=ThreatType.DNS_TUNNELING,
                level=ThreatLevel.HIGH,
                description="Base64-like encoding in subdomain (possible DNS tunneling)",
                score=0.7,
                details={"subdomain": subdomain[:50]},
            ))
        
        # Check for hex encoding
        if self.HEX_PATTERN.match(subdomain):
            threats.append(ThreatIndicator(
                threat_type=ThreatType.DNS_TUNNELING,
                level=ThreatLevel.HIGH,
                description="Hex-encoded data in subdomain (possible DNS tunneling)",
                score=0.7,
                details={"subdomain": subdomain[:50]},
            ))
        
        # Check for very long subdomain
        if len(subdomain) > 50:
            threats.append(ThreatIndicator(
                threat_type=ThreatType.DNS_TUNNELING,
                level=ThreatLevel.MEDIUM,
                description="Unusually long subdomain (possible DNS tunneling)",
                score=0.5,
                details={"length": len(subdomain)},
            ))
        
        # Check for many subdomain levels
        levels = subdomain.count(".")
        if levels >= 4:
            threats.append(ThreatIndicator(
                threat_type=ThreatType.DNS_TUNNELING,
                level=ThreatLevel.MEDIUM,
                description="Multiple subdomain levels (possible DNS tunneling)",
                score=0.4,
                details={"levels": levels + 1},
            ))
        
        return threats
    
    def _check_malicious_patterns(self, domain_info: Dict[str, Any]) -> List[ThreatIndicator]:
        """Check for known malicious patterns"""
        threats = []
        domain = domain_info.get("full_domain", "").lower()
        
        for pattern in self.MALICIOUS_PATTERNS:
            if re.search(pattern, domain, re.IGNORECASE):
                threats.append(ThreatIndicator(
                    threat_type=ThreatType.PHISHING,
                    level=ThreatLevel.HIGH,
                    description="Domain matches known phishing pattern",
                    score=0.8,
                    details={"pattern": pattern},
                ))
                break
        
        return threats
    
    def _check_custom_rules(self, domain_info: Dict[str, Any]) -> List[ThreatIndicator]:
        """Check custom detection rules"""
        threats = []
        domain = domain_info.get("full_domain", "")
        
        for rule in self._custom_rules:
            if rule["pattern"].search(domain):
                threats.append(ThreatIndicator(
                    threat_type=rule["threat_type"],
                    level=rule["level"],
                    description=rule["description"],
                    score=0.7,
                    details={"rule": rule["name"]},
                ))
        
        return threats
    
    def _check_domain_length(self, domain_info: Dict[str, Any]) -> List[ThreatIndicator]:
        """Check for suspicious domain length"""
        threats = []
        length = domain_info.get("length", 0)
        
        if length > 100:
            threats.append(ThreatIndicator(
                threat_type=ThreatType.LONG_DOMAIN,
                level=ThreatLevel.LOW,
                description=f"Unusually long domain name ({length} characters)",
                score=0.2,
                details={"length": length},
            ))
        
        return threats
    
    def _calculate_performance_score(self, query: DNSQuery) -> float:
        """Calculate performance score based on response time"""
        if not query.is_successful:
            return 0.0
        
        response_time = query.response_time_ms
        
        # Score based on response time thresholds
        if response_time < 50:
            return 1.0
        elif response_time < 100:
            return 0.9
        elif response_time < 200:
            return 0.7
        elif response_time < 500:
            return 0.5
        elif response_time < 1000:
            return 0.3
        else:
            return 0.1
    
    def _generate_recommendations(self, result: DNSAnalysisResult) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if result.is_suspicious:
            recommendations.append("⚠️ Investigate this domain before accessing")
        
        for threat in result.threats:
            if threat.threat_type == ThreatType.PHISHING:
                recommendations.append("🔒 Do not enter credentials on this domain")
            elif threat.threat_type == ThreatType.MALWARE:
                recommendations.append("🚫 Block this domain at firewall level")
            elif threat.threat_type == ThreatType.DNS_TUNNELING:
                recommendations.append("🔍 Monitor for data exfiltration")
            elif threat.threat_type == ThreatType.TYPOSQUATTING:
                recommendations.append("✏️ Verify correct domain spelling")
            elif threat.threat_type == ThreatType.SUSPICIOUS_TLD:
                recommendations.append("🌐 Exercise caution with this TLD")
        
        if result.performance_score < 0.5:
            recommendations.append("⏱️ Consider using a faster DNS server")
        
        return list(set(recommendations))  # Remove duplicates
    
    @staticmethod
    def _calculate_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not data:
            return 0.0
        
        counter = Counter(data.lower())
        length = len(data)
        
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def _calculate_consonant_vowel_ratio(text: str) -> float:
        """Calculate consonant to vowel ratio"""
        vowels = set("aeiou")
        consonants = set("bcdfghjklmnpqrstvwxyz")
        
        vowel_count = sum(1 for c in text.lower() if c in vowels)
        consonant_count = sum(1 for c in text.lower() if c in consonants)
        
        if vowel_count == 0:
            return float("inf") if consonant_count > 0 else 0.0
        
        return consonant_count / vowel_count
