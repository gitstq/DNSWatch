"""
🔍 DNSWatch - Lightweight Terminal DNS Query Monitor & Security Analysis Engine
轻量级终端DNS查询监控与安全分析引擎

A zero-dependency DNS monitoring tool with real-time query tracking,
suspicious domain detection, performance analysis, and beautiful TUI dashboard.
"""

__version__ = "1.0.0"
__author__ = "SOLO Agent"
__license__ = "MIT"

from dnswatch.monitor import DNSMonitor
from dnswatch.analyzer import DNSAnalyzer
from dnswatch.detector import ThreatDetector

__all__ = ["DNSMonitor", "DNSAnalyzer", "ThreatDetector", "__version__"]
