"""
DNS Analyzer Module

Comprehensive DNS query analysis with statistics,
trend detection, and reporting capabilities.
"""

import json
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from dnswatch.detector import ThreatDetector
from dnswatch.models import (
    DNSAnalysisResult,
    DNSQuery,
    DNSStatistics,
    QueryType,
    ThreatLevel,
    ThreatType,
)


class DNSAnalyzer:
    """
    DNS Query Analyzer
    
    Provides comprehensive analysis of DNS queries including
    statistics, trends, threat correlation, and reporting.
    """
    
    def __init__(
        self,
        enable_threat_detection: bool = True,
        threat_detector: Optional[ThreatDetector] = None,
    ):
        """
        Initialize DNS Analyzer.
        
        Args:
            enable_threat_detection: Enable threat detection
            threat_detector: Custom threat detector instance
        """
        self.enable_threat_detection = enable_threat_detection
        self.threat_detector = threat_detector or ThreatDetector()
        
        # Analysis data
        self._results: List[DNSAnalysisResult] = []
        self._domain_history: Dict[str, List[DNSQuery]] = defaultdict(list)
        self._ip_domain_map: Dict[str, List[str]] = defaultdict(list)
    
    def analyze(self, query: DNSQuery) -> DNSAnalysisResult:
        """
        Analyze a DNS query.
        
        Args:
            query: DNS query to analyze
            
        Returns:
            DNSAnalysisResult with analysis data
        """
        result = self.threat_detector.analyze(query) if self.enable_threat_detection else DNSAnalysisResult(query=query)
        
        # Track domain history
        self._domain_history[query.domain].append(query)
        
        # Track IP-domain mapping
        for record in query.records:
            if record.record_type in (QueryType.A, QueryType.AAAA):
                self._ip_domain_map[record.value].append(query.domain)
        
        # Store result
        self._results.append(result)
        
        return result
    
    def analyze_batch(self, queries: List[DNSQuery]) -> List[DNSAnalysisResult]:
        """
        Analyze multiple queries.
        
        Args:
            queries: List of DNS queries
            
        Returns:
            List of analysis results
        """
        return [self.analyze(q) for q in queries]
    
    def get_statistics(self, time_window: Optional[timedelta] = None) -> DNSStatistics:
        """
        Get DNS statistics.
        
        Args:
            time_window: Optional time window for filtering
            
        Returns:
            DNSStatistics with aggregated data
        """
        stats = DNSStatistics()
        
        # Filter results by time window
        results = self._results
        if time_window:
            cutoff = datetime.now() - time_window
            results = [r for r in results if r.query.timestamp >= cutoff]
        
        stats.total_queries = len(results)
        if stats.total_queries == 0:
            return stats
        
        # Calculate success/failure
        response_times = []
        for result in results:
            if result.query.is_successful:
                stats.successful_queries += 1
            else:
                stats.failed_queries += 1
            
            response_times.append(result.query.response_time_ms)
        
        # Response time statistics
        if response_times:
            stats.avg_response_time_ms = sum(response_times) / len(response_times)
            stats.min_response_time_ms = min(response_times)
            stats.max_response_time_ms = max(response_times)
        
        # Query type distribution
        type_counts: Dict[str, int] = defaultdict(int)
        for result in results:
            type_counts[result.query.query_type.value] += 1
        stats.query_types = dict(type_counts)
        
        # Top domains
        domain_counts: Dict[str, int] = defaultdict(int)
        for result in results:
            domain_counts[result.query.domain] += 1
        
        sorted_domains = sorted(
            domain_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        stats.top_domains = sorted_domains[:20]
        
        # Threat statistics
        for result in results:
            if result.is_suspicious:
                stats.suspicious_queries += 1
            else:
                stats.safe_queries += 1
            
            for threat in result.threats:
                key = threat.threat_type.value
                stats.threat_breakdown[key] = stats.threat_breakdown.get(key, 0) + 1
        
        # TLD distribution
        tld_counts: Dict[str, int] = defaultdict(int)
        for result in results:
            tld = result.query.tld
            if tld:
                tld_counts[tld] += 1
        stats.tld_distribution = dict(tld_counts)
        
        return stats
    
    def get_domain_history(self, domain: str) -> List[DNSQuery]:
        """
        Get query history for a domain.
        
        Args:
            domain: Domain to look up
            
        Returns:
            List of historical queries
        """
        return self._domain_history.get(domain, [])
    
    def get_domains_for_ip(self, ip: str) -> List[str]:
        """
        Get domains associated with an IP.
        
        Args:
            ip: IP address to look up
            
        Returns:
            List of associated domains
        """
        return list(set(self._ip_domain_map.get(ip, [])))
    
    def get_suspicious_domains(self) -> List[Tuple[str, int, ThreatLevel]]:
        """
        Get list of suspicious domains.
        
        Returns:
            List of (domain, count, max_threat_level) tuples
        """
        suspicious = []
        
        for domain, queries in self._domain_history.items():
            # Get results for this domain
            domain_results = [r for r in self._results if r.query.domain == domain]
            
            if any(r.is_suspicious for r in domain_results):
                max_level = max(
                    (r.max_threat_level for r in domain_results),
                    key=lambda l: {
                        ThreatLevel.SAFE: 0,
                        ThreatLevel.LOW: 1,
                        ThreatLevel.MEDIUM: 2,
                        ThreatLevel.HIGH: 3,
                        ThreatLevel.CRITICAL: 4,
                    }.get(l, 0)
                )
                suspicious.append((domain, len(queries), max_level))
        
        # Sort by threat level and count
        return sorted(
            suspicious,
            key=lambda x: (
                {
                    ThreatLevel.CRITICAL: 4,
                    ThreatLevel.HIGH: 3,
                    ThreatLevel.MEDIUM: 2,
                    ThreatLevel.LOW: 1,
                    ThreatLevel.SAFE: 0,
                }.get(x[2], 0),
                x[1]
            ),
            reverse=True
        )
    
    def get_threat_summary(self) -> Dict[str, Any]:
        """
        Get threat detection summary.
        
        Returns:
            Dictionary with threat summary data
        """
        summary = {
            "total_queries": len(self._results),
            "safe_queries": 0,
            "suspicious_queries": 0,
            "threat_breakdown": {},
            "top_threats": [],
            "high_risk_domains": [],
        }
        
        threat_counts: Dict[ThreatType, int] = defaultdict(int)
        
        for result in self._results:
            if result.is_suspicious:
                summary["suspicious_queries"] += 1
            else:
                summary["safe_queries"] += 1
            
            for threat in result.threats:
                threat_counts[threat.threat_type] += 1
        
        # Threat breakdown
        summary["threat_breakdown"] = {
            t.value: c for t, c in threat_counts.items()
        }
        
        # Top threats
        sorted_threats = sorted(
            threat_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        summary["top_threats"] = [
            {"type": t.value, "count": c}
            for t, c in sorted_threats[:10]
        ]
        
        # High risk domains
        high_risk = [
            (domain, level.value)
            for domain, _, level in self.get_suspicious_domains()[:10]
            if level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)
        ]
        summary["high_risk_domains"] = [
            {"domain": d, "level": l}
            for d, l in high_risk
        ]
        
        return summary
    
    def get_performance_report(self) -> Dict[str, Any]:
        """
        Get DNS performance report.
        
        Returns:
            Dictionary with performance data
        """
        if not self._results:
            return {
                "avg_response_time_ms": 0,
                "min_response_time_ms": 0,
                "max_response_time_ms": 0,
                "p50_response_time_ms": 0,
                "p95_response_time_ms": 0,
                "p99_response_time_ms": 0,
                "slow_queries": [],
            }
        
        response_times = sorted(
            [r.query.response_time_ms for r in self._results]
        )
        
        n = len(response_times)
        
        def percentile(p: float) -> float:
            idx = int(n * p / 100)
            return response_times[min(idx, n - 1)]
        
        # Find slow queries (> 1 second)
        slow_queries = [
            {
                "domain": r.query.domain,
                "response_time_ms": r.query.response_time_ms,
                "timestamp": r.query.timestamp.isoformat(),
            }
            for r in self._results
            if r.query.response_time_ms > 1000
        ]
        
        return {
            "avg_response_time_ms": sum(response_times) / n,
            "min_response_time_ms": response_times[0],
            "max_response_time_ms": response_times[-1],
            "p50_response_time_ms": percentile(50),
            "p95_response_time_ms": percentile(95),
            "p99_response_time_ms": percentile(99),
            "slow_queries": sorted(
                slow_queries,
                key=lambda x: x["response_time_ms"],
                reverse=True
            )[:20],
        }
    
    def generate_report(
        self,
        format: str = "json",
        include_queries: bool = False,
    ) -> str:
        """
        Generate comprehensive analysis report.
        
        Args:
            format: Report format (json, markdown, html)
            include_queries: Include individual query data
            
        Returns:
            Report as string
        """
        stats = self.get_statistics()
        threat_summary = self.get_threat_summary()
        performance = self.get_performance_report()
        
        report_data = {
            "generated_at": datetime.now().isoformat(),
            "statistics": {
                "total_queries": stats.total_queries,
                "successful_queries": stats.successful_queries,
                "failed_queries": stats.failed_queries,
                "success_rate": stats.success_rate,
                "suspicious_rate": stats.suspicious_rate,
                "query_types": stats.query_types,
                "top_domains": stats.top_domains[:10],
                "tld_distribution": dict(list(stats.tld_distribution.items())[:10]),
            },
            "threats": threat_summary,
            "performance": performance,
        }
        
        if include_queries:
            report_data["queries"] = [
                {
                    "domain": r.query.domain,
                    "type": r.query.query_type.value,
                    "response_time_ms": r.query.response_time_ms,
                    "is_successful": r.query.is_successful,
                    "is_suspicious": r.is_suspicious,
                    "threats": [
                        {
                            "type": t.threat_type.value,
                            "level": t.level.value,
                            "description": t.description,
                        }
                        for t in r.threats
                    ],
                }
                for r in self._results
            ]
        
        if format == "json":
            return json.dumps(report_data, indent=2)
        
        elif format == "markdown":
            return self._generate_markdown_report(report_data)
        
        elif format == "html":
            return self._generate_html_report(report_data)
        
        raise ValueError(f"Unsupported format: {format}")
    
    def _generate_markdown_report(self, data: Dict[str, Any]) -> str:
        """Generate Markdown format report"""
        lines = [
            "# 🔍 DNSWatch Analysis Report",
            "",
            f"**Generated:** {data['generated_at']}",
            "",
            "## 📊 Statistics",
            "",
            f"- **Total Queries:** {data['statistics']['total_queries']}",
            f"- **Successful:** {data['statistics']['successful_queries']}",
            f"- **Failed:** {data['statistics']['failed_queries']}",
            f"- **Success Rate:** {data['statistics']['success_rate']:.1%}",
            f"- **Suspicious Rate:** {data['statistics']['suspicious_rate']:.1%}",
            "",
            "## 🛡️ Threat Summary",
            "",
            f"- **Safe Queries:** {data['threats']['safe_queries']}",
            f"- **Suspicious Queries:** {data['threats']['suspicious_queries']}",
            "",
            "### Threat Breakdown",
            "",
        ]
        
        for threat_type, count in data['threats']['threat_breakdown'].items():
            lines.append(f"- **{threat_type}:** {count}")
        
        lines.extend([
            "",
            "## ⏱️ Performance",
            "",
            f"- **Average Response Time:** {data['performance']['avg_response_time_ms']:.2f}ms",
            f"- **P50:** {data['performance']['p50_response_time_ms']:.2f}ms",
            f"- **P95:** {data['performance']['p95_response_time_ms']:.2f}ms",
            f"- **P99:** {data['performance']['p99_response_time_ms']:.2f}ms",
            "",
        ])
        
        return "\n".join(lines)
    
    def _generate_html_report(self, data: Dict[str, Any]) -> str:
        """Generate HTML format report"""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNSWatch Analysis Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #2563eb; }}
        h2 {{ color: #1f2937; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: #f9fafb; padding: 20px; border-radius: 8px; border-left: 4px solid #2563eb; }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: #1f2937; }}
        .stat-label {{ color: #6b7280; }}
        .threat-item {{ padding: 10px; margin: 5px 0; background: #fef3c7; border-radius: 4px; }}
        .high-risk {{ background: #fee2e2; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }}
        th {{ background: #f9fafb; }}
    </style>
</head>
<body>
    <h1>🔍 DNSWatch Analysis Report</h1>
    <p><strong>Generated:</strong> {data['generated_at']}</p>
    
    <h2>📊 Statistics</h2>
    <div class="stat-grid">
        <div class="stat-card">
            <div class="stat-value">{data['statistics']['total_queries']}</div>
            <div class="stat-label">Total Queries</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{data['statistics']['success_rate']:.1%}</div>
            <div class="stat-label">Success Rate</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{data['statistics']['suspicious_rate']:.1%}</div>
            <div class="stat-label">Suspicious Rate</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{data['performance']['avg_response_time_ms']:.0f}ms</div>
            <div class="stat-label">Avg Response Time</div>
        </div>
    </div>
    
    <h2>🛡️ Threat Summary</h2>
    <p><strong>Safe Queries:</strong> {data['threats']['safe_queries']}</p>
    <p><strong>Suspicious Queries:</strong> {data['threats']['suspicious_queries']}</p>
    
    <h2>⏱️ Performance</h2>
    <table>
        <tr><th>Metric</th><th>Value</th></tr>
        <tr><td>Average</td><td>{data['performance']['avg_response_time_ms']:.2f}ms</td></tr>
        <tr><td>P50</td><td>{data['performance']['p50_response_time_ms']:.2f}ms</td></tr>
        <tr><td>P95</td><td>{data['performance']['p95_response_time_ms']:.2f}ms</td></tr>
        <tr><td>P99</td><td>{data['performance']['p99_response_time_ms']:.2f}ms</td></tr>
    </table>
</body>
</html>"""
    
    def reset(self) -> None:
        """Reset all analysis data"""
        self._results.clear()
        self._domain_history.clear()
        self._ip_domain_map.clear()
