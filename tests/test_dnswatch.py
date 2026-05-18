"""
DNSWatch Tests

Unit tests for DNS monitoring and analysis functionality.
"""

import pytest
from datetime import datetime

from dnswatch.models import (
    DNSQuery,
    DNSRecord,
    QueryType,
    ThreatLevel,
    ThreatType,
    is_valid_domain,
    parse_domain,
)
from dnswatch.monitor import DNSMonitor
from dnswatch.detector import ThreatDetector
from dnswatch.analyzer import DNSAnalyzer


class TestModels:
    """Test data models"""
    
    def test_dns_query_creation(self):
        """Test DNSQuery creation"""
        query = DNSQuery(
            timestamp=datetime.now(),
            domain="example.com",
            query_type=QueryType.A,
            nameserver="8.8.8.8",
            response_time_ms=50.0,
        )
        
        assert query.domain == "example.com"
        assert query.query_type == QueryType.A
        assert query.is_successful is True
        assert query.tld == "com"
    
    def test_dns_query_with_error(self):
        """Test DNSQuery with error"""
        query = DNSQuery(
            timestamp=datetime.now(),
            domain="invalid.invalid",
            query_type=QueryType.A,
            nameserver="8.8.8.8",
            response_time_ms=100.0,
            error="NXDOMAIN",
        )
        
        assert query.is_successful is False
        assert query.error == "NXDOMAIN"
    
    def test_parse_domain(self):
        """Test domain parsing"""
        info = parse_domain("www.example.com")
        
        assert info["full_domain"] == "www.example.com"
        assert info["tld"] == "com"
        assert info["domain"] == "example.com"
        assert info["subdomain"] == "www"
        assert info["length"] == 15
    
    def test_is_valid_domain(self):
        """Test domain validation"""
        assert is_valid_domain("example.com") is True
        assert is_valid_domain("www.example.com") is True
        assert is_valid_domain("sub.domain.example.com") is True
        assert is_valid_domain("") is False
        assert is_valid_domain("a" * 300) is False
        assert is_valid_domain("invalid") is False


class TestMonitor:
    """Test DNS monitor"""
    
    def test_monitor_creation(self):
        """Test monitor initialization"""
        monitor = DNSMonitor()
        
        assert len(monitor.nameservers) > 0
        assert monitor.timeout == 5.0
    
    def test_resolve_domain(self):
        """Test domain resolution"""
        monitor = DNSMonitor()
        query = monitor.resolve("google.com", QueryType.A)
        
        assert query.domain == "google.com"
        assert query.query_type == QueryType.A
        assert query.response_time_ms >= 0
    
    def test_get_statistics(self):
        """Test statistics collection"""
        monitor = DNSMonitor()
        
        # Resolve some domains
        monitor.resolve("google.com", QueryType.A)
        monitor.resolve("github.com", QueryType.A)
        
        stats = monitor.get_statistics()
        
        assert stats.total_queries == 2
        assert stats.successful_queries >= 0
    
    def test_batch_resolve(self):
        """Test batch resolution"""
        monitor = DNSMonitor()
        
        domains = ["google.com", "github.com", "example.com"]
        results = monitor.batch_resolve(domains, QueryType.A)
        
        assert len(results) == 3
        for result in results:
            assert result.domain in domains


class TestDetector:
    """Test threat detector"""
    
    def test_detector_creation(self):
        """Test detector initialization"""
        detector = ThreatDetector()
        
        assert detector.enable_dga_detection is True
        assert detector.enable_typosquatting is True
    
    def test_analyze_safe_domain(self):
        """Test analysis of safe domain"""
        detector = ThreatDetector()
        
        query = DNSQuery(
            timestamp=datetime.now(),
            domain="google.com",
            query_type=QueryType.A,
            nameserver="8.8.8.8",
            response_time_ms=50.0,
        )
        
        result = detector.analyze(query)
        
        # google.com should be relatively safe
        assert result.query.domain == "google.com"
    
    def test_analyze_suspicious_tld(self):
        """Test detection of suspicious TLD"""
        detector = ThreatDetector()
        
        query = DNSQuery(
            timestamp=datetime.now(),
            domain="example.tk",
            query_type=QueryType.A,
            nameserver="8.8.8.8",
            response_time_ms=50.0,
        )
        
        result = detector.analyze(query)
        
        # Should detect suspicious TLD
        threat_types = [t.threat_type for t in result.threats]
        assert ThreatType.SUSPICIOUS_TLD in threat_types
    
    def test_analyze_long_domain(self):
        """Test detection of long domain"""
        detector = ThreatDetector()
        
        long_domain = "a" * 150 + ".com"
        query = DNSQuery(
            timestamp=datetime.now(),
            domain=long_domain,
            query_type=QueryType.A,
            nameserver="8.8.8.8",
            response_time_ms=50.0,
        )
        
        result = detector.analyze(query)
        
        # Should detect long domain
        threat_types = [t.threat_type for t in result.threats]
        assert ThreatType.LONG_DOMAIN in threat_types
    
    def test_allowlist(self):
        """Test allowlist functionality"""
        detector = ThreatDetector()
        detector.add_to_allowlist("trusted.example.com")
        
        query = DNSQuery(
            timestamp=datetime.now(),
            domain="trusted.example.com",
            query_type=QueryType.A,
            nameserver="8.8.8.8",
            response_time_ms=50.0,
        )
        
        result = detector.analyze(query)
        
        # Allowlisted domain should have no threats
        assert len(result.threats) == 0
    
    def test_blocklist(self):
        """Test blocklist functionality"""
        detector = ThreatDetector()
        detector.add_to_blocklist("malicious.example.com")
        
        query = DNSQuery(
            timestamp=datetime.now(),
            domain="malicious.example.com",
            query_type=QueryType.A,
            nameserver="8.8.8.8",
            response_time_ms=50.0,
        )
        
        result = detector.analyze(query)
        
        # Blocklisted domain should be marked as critical
        assert result.is_suspicious is True
        assert result.max_threat_level == ThreatLevel.CRITICAL


class TestAnalyzer:
    """Test DNS analyzer"""
    
    def test_analyzer_creation(self):
        """Test analyzer initialization"""
        analyzer = DNSAnalyzer()
        
        assert analyzer.enable_threat_detection is True
    
    def test_analyze_query(self):
        """Test query analysis"""
        analyzer = DNSAnalyzer()
        
        query = DNSQuery(
            timestamp=datetime.now(),
            domain="example.com",
            query_type=QueryType.A,
            nameserver="8.8.8.8",
            response_time_ms=50.0,
        )
        
        result = analyzer.analyze(query)
        
        assert result.query.domain == "example.com"
    
    def test_get_statistics(self):
        """Test statistics generation"""
        analyzer = DNSAnalyzer()
        
        # Analyze some queries
        for domain in ["google.com", "github.com", "example.com"]:
            query = DNSQuery(
                timestamp=datetime.now(),
                domain=domain,
                query_type=QueryType.A,
                nameserver="8.8.8.8",
                response_time_ms=50.0,
            )
            analyzer.analyze(query)
        
        stats = analyzer.get_statistics()
        
        assert stats.total_queries == 3
    
    def test_generate_report(self):
        """Test report generation"""
        analyzer = DNSAnalyzer()
        
        query = DNSQuery(
            timestamp=datetime.now(),
            domain="example.com",
            query_type=QueryType.A,
            nameserver="8.8.8.8",
            response_time_ms=50.0,
        )
        analyzer.analyze(query)
        
        report = analyzer.generate_report(format="json")
        
        assert "statistics" in report
        assert "threats" in report
        assert "performance" in report
    
    def test_get_threat_summary(self):
        """Test threat summary generation"""
        analyzer = DNSAnalyzer()
        
        # Analyze a suspicious domain
        query = DNSQuery(
            timestamp=datetime.now(),
            domain="example.tk",
            query_type=QueryType.A,
            nameserver="8.8.8.8",
            response_time_ms=50.0,
        )
        analyzer.analyze(query)
        
        summary = analyzer.get_threat_summary()
        
        assert "total_queries" in summary
        assert "threat_breakdown" in summary


class TestIntegration:
    """Integration tests"""
    
    def test_full_workflow(self):
        """Test complete monitoring workflow"""
        monitor = DNSMonitor()
        analyzer = DNSAnalyzer()
        
        # Resolve and analyze
        query = monitor.resolve("github.com", QueryType.A)
        result = analyzer.analyze(query)
        
        # Get statistics
        stats = analyzer.get_statistics()
        
        assert stats.total_queries >= 1
        assert result.query.domain == "github.com"
    
    def test_batch_analysis(self):
        """Test batch analysis workflow"""
        monitor = DNSMonitor()
        analyzer = DNSAnalyzer()
        
        domains = ["google.com", "github.com", "example.com"]
        
        for domain in domains:
            query = monitor.resolve(domain, QueryType.A)
            analyzer.analyze(query)
        
        stats = analyzer.get_statistics()
        
        assert stats.total_queries == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
