"""
DNSWatch TUI Dashboard

Beautiful terminal dashboard for real-time DNS monitoring
with live statistics, threat alerts, and performance metrics.
"""

import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from dnswatch.analyzer import DNSAnalyzer
from dnswatch.detector import ThreatDetector
from dnswatch.models import DNSQuery, DNSStatistics, ThreatLevel
from dnswatch.monitor import DNSMonitor


class DNSWatchDashboard:
    """
    Real-time DNS Monitoring Dashboard
    
    Provides a beautiful terminal interface for monitoring
    DNS queries, threats, and performance metrics.
    """
    
    def __init__(
        self,
        monitor: Optional[DNSMonitor] = None,
        analyzer: Optional[DNSAnalyzer] = None,
        refresh_rate: float = 1.0,
    ):
        """
        Initialize Dashboard.
        
        Args:
            monitor: DNS Monitor instance
            analyzer: DNS Analyzer instance
            refresh_rate: Dashboard refresh rate in seconds
        """
        self.monitor = monitor or DNSMonitor()
        self.analyzer = analyzer or DNSAnalyzer()
        self.refresh_rate = refresh_rate
        
        self.console = Console()
        self._running = False
        self._recent_queries: List[DNSQuery] = []
        self._alerts: List[Dict[str, Any]] = []
        
        # Set up query callback
        self.monitor.add_query_callback(self._on_query)
    
    def _on_query(self, query: DNSQuery) -> None:
        """Handle new query event"""
        # Analyze query
        result = self.analyzer.analyze(query)
        
        # Track recent queries
        self._recent_queries.append(query)
        if len(self._recent_queries) > 50:
            self._recent_queries.pop(0)
        
        # Generate alerts for suspicious queries
        if result.is_suspicious:
            self._alerts.append({
                "timestamp": datetime.now(),
                "domain": query.domain,
                "level": result.max_threat_level.value,
                "threats": [t.threat_type.value for t in result.threats],
            })
            if len(self._alerts) > 20:
                self._alerts.pop(0)
    
    def _create_header(self) -> Panel:
        """Create dashboard header"""
        return Panel(
            Text.from_markup(
                "[bold blue]🔍 DNSWatch[/bold blue] - "
                "[cyan]Real-time DNS Monitor & Security Analysis[/cyan]"
            ),
            style="bold white on blue",
        )
    
    def _create_stats_panel(self, stats: DNSStatistics) -> Panel:
        """Create statistics panel"""
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green", justify="right")
        
        table.add_row("Total Queries", str(stats.total_queries))
        table.add_row("Successful", f"{stats.successful_queries} ({stats.success_rate:.1%})")
        table.add_row("Failed", str(stats.failed_queries))
        table.add_row("Suspicious", f"{stats.suspicious_queries} ({stats.suspicious_rate:.1%})")
        table.add_row(
            "Avg Response",
            f"{stats.avg_response_time_ms:.1f}ms" if stats.avg_response_time_ms > 0 else "N/A"
        )
        
        return Panel(table, title="📊 Statistics", border_style="blue")
    
    def _create_query_type_panel(self, stats: DNSStatistics) -> Panel:
        """Create query type distribution panel"""
        if not stats.query_types:
            return Panel("No data", title="📝 Query Types", border_style="cyan")
        
        table = Table(show_header=True, box=None)
        table.add_column("Type", style="cyan")
        table.add_column("Count", style="green", justify="right")
        table.add_column("Bar", style="blue")
        
        max_count = max(stats.query_types.values())
        
        for qtype, count in sorted(
            stats.query_types.items(),
            key=lambda x: x[1],
            reverse=True
        )[:8]:
            bar_width = int(20 * count / max_count) if max_count > 0 else 0
            bar = "█" * bar_width + "░" * (20 - bar_width)
            table.add_row(qtype, str(count), bar)
        
        return Panel(table, title="📝 Query Types", border_style="cyan")
    
    def _create_top_domains_panel(self, stats: DNSStatistics) -> Panel:
        """Create top domains panel"""
        if not stats.top_domains:
            return Panel("No data", title="🌐 Top Domains", border_style="green")
        
        table = Table(show_header=True, box=None)
        table.add_column("#", style="dim", width=3)
        table.add_column("Domain", style="cyan")
        table.add_column("Count", style="green", justify="right")
        
        for i, (domain, count) in enumerate(stats.top_domains[:10], 1):
            # Truncate long domains
            display_domain = domain[:35] + "..." if len(domain) > 35 else domain
            table.add_row(str(i), display_domain, str(count))
        
        return Panel(table, title="🌐 Top Domains", border_style="green")
    
    def _create_recent_queries_panel(self) -> Panel:
        """Create recent queries panel"""
        if not self._recent_queries:
            return Panel("No queries yet", title="📋 Recent Queries", border_style="yellow")
        
        table = Table(show_header=True, box=None)
        table.add_column("Time", style="dim", width=8)
        table.add_column("Domain", style="cyan")
        table.add_column("Type", style="blue", width=6)
        table.add_column("Status", style="green", width=8)
        table.add_column("Time", style="yellow", width=8)
        
        for query in self._recent_queries[-15:]:
            time_str = query.timestamp.strftime("%H:%M:%S")
            domain = query.domain[:30] + "..." if len(query.domain) > 30 else query.domain
            status = "✓" if query.is_successful else "✗"
            status_style = "green" if query.is_successful else "red"
            response = f"{query.response_time_ms:.0f}ms"
            
            table.add_row(
                time_str,
                domain,
                query.query_type.value,
                f"[{status_style}]{status}[/{status_style}]",
                response,
            )
        
        return Panel(table, title="📋 Recent Queries", border_style="yellow")
    
    def _create_alerts_panel(self) -> Panel:
        """Create threat alerts panel"""
        if not self._alerts:
            return Panel(
                "[green]✓ No threats detected[/green]",
                title="🚨 Threat Alerts",
                border_style="red"
            )
        
        table = Table(show_header=True, box=None)
        table.add_column("Time", style="dim", width=8)
        table.add_column("Domain", style="cyan")
        table.add_column("Level", style="bold")
        table.add_column("Threats", style="red")
        
        for alert in self._alerts[-10:]:
            time_str = alert["timestamp"].strftime("%H:%M:%S")
            domain = alert["domain"][:25] + "..." if len(alert["domain"]) > 25 else alert["domain"]
            
            level_style = {
                "low": "yellow",
                "medium": "orange1",
                "high": "red",
                "critical": "bold red",
            }.get(alert["level"], "white")
            
            threats = ", ".join(alert["threats"][:2])
            if len(alert["threats"]) > 2:
                threats += f" +{len(alert['threats']) - 2}"
            
            table.add_row(
                time_str,
                domain,
                f"[{level_style}]{alert['level'].upper()}[/{level_style}]",
                threats,
            )
        
        return Panel(table, title="🚨 Threat Alerts", border_style="red")
    
    def _create_performance_panel(self) -> Panel:
        """Create performance metrics panel"""
        perf = self.analyzer.get_performance_report()
        
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green", justify="right")
        
        table.add_row("Average", f"{perf['avg_response_time_ms']:.1f}ms")
        table.add_row("P50", f"{perf['p50_response_time_ms']:.1f}ms")
        table.add_row("P95", f"{perf['p95_response_time_ms']:.1f}ms")
        table.add_row("P99", f"{perf['p99_response_time_ms']:.1f}ms")
        table.add_row("Slow Queries", str(len(perf['slow_queries'])))
        
        return Panel(table, title="⏱️ Performance", border_style="magenta")
    
    def _create_tld_panel(self, stats: DNSStatistics) -> Panel:
        """Create TLD distribution panel"""
        if not stats.tld_distribution:
            return Panel("No data", title="🌍 TLD Distribution", border_style="blue")
        
        table = Table(show_header=True, box=None)
        table.add_column("TLD", style="cyan")
        table.add_column("Count", style="green", justify="right")
        
        sorted_tlds = sorted(
            stats.tld_distribution.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        for tld, count in sorted_tlds:
            # Highlight suspicious TLDs
            style = "red" if tld.lower() in ThreatDetector.SUSPICIOUS_TLDS else None
            table.add_row(f".{tld}" if style is None else f"[red].{tld}[/red]", str(count))
        
        return Panel(table, title="🌍 TLD Distribution", border_style="blue")
    
    def _create_layout(self) -> Layout:
        """Create dashboard layout"""
        layout = Layout()
        
        layout.split(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=1),
        )
        
        layout["body"].split_row(
            Layout(name="left"),
            Layout(name="right"),
        )
        
        layout["left"].split(
            Layout(name="stats", size=8),
            Layout(name="performance", size=7),
            Layout(name="query_types", size=10),
            Layout(name="tld", size=12),
        )
        
        layout["right"].split(
            Layout(name="recent", size=18),
            Layout(name="alerts"),
        )
        
        return layout
    
    def _render_dashboard(self) -> Layout:
        """Render complete dashboard"""
        stats = self.analyzer.get_statistics()
        
        layout = self._create_layout()
        
        layout["header"].update(self._create_header())
        layout["stats"].update(self._create_stats_panel(stats))
        layout["performance"].update(self._create_performance_panel())
        layout["query_types"].update(self._create_query_type_panel(stats))
        layout["tld"].update(self._create_tld_panel(stats))
        layout["recent"].update(self._create_recent_queries_panel())
        layout["alerts"].update(self._create_alerts_panel())
        layout["footer"].update(
            Text.from_markup(
                "[dim]Press Ctrl+C to stop | "
                f"Last update: {datetime.now().strftime('%H:%M:%S')}[/dim]"
            )
        )
        
        return layout
    
    def run(self, domains: Optional[List[str]] = None) -> None:
        """
        Run the monitoring dashboard.
        
        Args:
            domains: Optional list of domains to monitor
        """
        self._running = True
        
        # Start monitoring loop
        try:
            with Live(
                self._render_dashboard(),
                console=self.console,
                refresh_per_second=1 / self.refresh_rate,
            ) as live:
                while self._running:
                    # Resolve domains if provided
                    if domains:
                        for domain in domains:
                            self.monitor.resolve(domain)
                    
                    time.sleep(self.refresh_rate)
                    live.update(self._render_dashboard())
                    
        except KeyboardInterrupt:
            self._running = False
            self.console.print("\n[yellow]Monitoring stopped.[/yellow]")
    
    def stop(self) -> None:
        """Stop the dashboard"""
        self._running = False
    
    def add_query(self, query: DNSQuery) -> None:
        """
        Manually add a query to the dashboard.
        
        Args:
            query: DNS query to add
        """
        self._on_query(query)
