"""
DNSWatch CLI

Command-line interface for DNS monitoring and analysis.
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from dnswatch import __version__
from dnswatch.analyzer import DNSAnalyzer
from dnswatch.detector import ThreatDetector
from dnswatch.models import QueryType, ThreatLevel
from dnswatch.monitor import DNSMonitor
from dnswatch.tui.dashboard import DNSWatchDashboard

console = Console()


def print_version(ctx, param, value):
    """Print version and exit"""
    if not value or ctx.resilient_parsing:
        return
    console.print(f"[bold blue]DNSWatch[/bold blue] version {__version__}")
    ctx.exit()


@click.group()
@click.option(
    "--version",
    "-v",
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
    help="Show version and exit",
)
def cli():
    """
    🔍 DNSWatch - Lightweight Terminal DNS Monitor & Security Analysis Engine
    
    Real-time DNS query monitoring with threat detection and performance analysis.
    """
    pass


@cli.command()
@click.argument("domain")
@click.option(
    "--type", "-t",
    type=click.Choice(["A", "AAAA", "MX", "CNAME", "TXT", "NS", "SOA", "PTR"]),
    default="A",
    help="DNS query type (default: A)",
)
@click.option(
    "--nameserver", "-n",
    default=None,
    help="DNS server to use (default: 8.8.8.8)",
)
@click.option(
    "--analyze", "-a",
    is_flag=True,
    help="Perform security analysis",
)
@click.option(
    "--json", "-j",
    "output_json",
    is_flag=True,
    help="Output in JSON format",
)
def resolve(
    domain: str,
    type: str,
    nameserver: Optional[str],
    analyze: bool,
    output_json: bool,
):
    """
    Resolve a DNS query for a domain.
    
    Example: dnswatch resolve google.com --type A --analyze
    """
    monitor = DNSMonitor(nameservers=[nameserver] if nameserver else None)
    query_type = QueryType(type)
    
    result = monitor.resolve(domain, query_type)
    
    if analyze:
        analyzer = DNSAnalyzer()
        analysis = analyzer.analyze(result)
    
    if output_json:
        data = {
            "domain": result.domain,
            "query_type": result.query_type.value,
            "nameserver": result.nameserver,
            "response_time_ms": result.response_time_ms,
            "is_successful": result.is_successful,
            "error": result.error,
            "records": [
                {
                    "name": r.name,
                    "type": r.record_type.value,
                    "ttl": r.ttl,
                    "value": r.value,
                    "priority": r.priority,
                }
                for r in result.records
            ],
        }
        
        if analyze:
            data["analysis"] = {
                "is_suspicious": analysis.is_suspicious,
                "threat_level": analysis.max_threat_level.value,
                "threats": [
                    {
                        "type": t.threat_type.value,
                        "level": t.level.value,
                        "description": t.description,
                    }
                    for t in analysis.threats
                ],
                "recommendations": analysis.recommendations,
            }
        
        console.print_json(data)
    else:
        # Display results in table format
        table = Table(title=f"🔍 DNS Query: {domain}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Domain", result.domain)
        table.add_row("Query Type", result.query_type.value)
        table.add_row("Nameserver", result.nameserver)
        table.add_row("Response Time", f"{result.response_time_ms:.2f}ms")
        table.add_row("Status", "✓ Success" if result.is_successful else f"✗ {result.error or 'Failed'}")
        
        console.print(table)
        
        if result.records:
            records_table = Table(title="📋 DNS Records")
            records_table.add_column("Name", style="cyan")
            records_table.add_column("Type", style="blue")
            records_table.add_column("TTL", style="dim")
            records_table.add_column("Value", style="green")
            
            for record in result.records:
                records_table.add_row(
                    record.name,
                    record.record_type.value,
                    str(record.ttl),
                    record.value,
                )
            
            console.print(records_table)
        
        if analyze:
            if analysis.is_suspicious:
                console.print(Panel(
                    f"[bold red]⚠️ Suspicious Domain Detected[/bold red]\n\n"
                    f"Threat Level: [bold]{analysis.max_threat_level.value.upper()}[/bold]\n\n"
                    + "\n".join(f"• {t.description}" for t in analysis.threats)
                    + "\n\n"
                    + "\n".join(f"💡 {r}" for r in analysis.recommendations),
                    title="🛡️ Security Analysis",
                    border_style="red",
                ))
            else:
                console.print(Panel(
                    "[bold green]✓ Domain appears safe[/bold green]\n\n"
                    + "\n".join(f"💡 {r}" for r in analysis.recommendations) if analysis.recommendations else "No security concerns detected.",
                    title="🛡️ Security Analysis",
                    border_style="green",
                ))


@cli.command()
@click.argument("domains", nargs=-1, required=True)
@click.option(
    "--type", "-t",
    type=click.Choice(["A", "AAAA", "MX", "CNAME", "TXT", "NS"]),
    default="A",
    help="DNS query type (default: A)",
)
@click.option(
    "--nameserver", "-n",
    default=None,
    help="DNS server to use",
)
@click.option(
    "--analyze", "-a",
    is_flag=True,
    help="Perform security analysis",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Output file path",
)
def batch(
    domains: List[str],
    type: str,
    nameserver: Optional[str],
    analyze: bool,
    output: Optional[str],
):
    """
    Resolve multiple domains in batch.
    
    Example: dnswatch batch google.com github.com --analyze
    """
    monitor = DNSMonitor(nameservers=[nameserver] if nameserver else None)
    analyzer = DNSAnalyzer() if analyze else None
    query_type = QueryType(type)
    
    console.print(f"[cyan]Resolving {len(domains)} domains...[/cyan]")
    
    results = monitor.batch_resolve(list(domains), query_type)
    
    if analyze:
        for result in results:
            analyzer.analyze(result)
    
    # Display results
    table = Table(title="📋 Batch Results")
    table.add_column("Domain", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Time", style="yellow")
    table.add_column("Records", style="blue")
    
    if analyze:
        table.add_column("Threat Level", style="red")
    
    for result in results:
        status = "✓" if result.is_successful else "✗"
        status_style = "green" if result.is_successful else "red"
        records_count = len(result.records)
        
        row = [
            result.domain,
            f"[{status_style}]{status}[/{status_style}]",
            f"{result.response_time_ms:.0f}ms",
            str(records_count),
        ]
        
        if analyze and analyzer:
            analysis = [a for a in analyzer._results if a.query.domain == result.domain]
            if analysis:
                level = analysis[0].max_threat_level.value.upper()
                level_style = {
                    "SAFE": "green",
                    "LOW": "yellow",
                    "MEDIUM": "orange1",
                    "HIGH": "red",
                    "CRITICAL": "bold red",
                }.get(level, "white")
                row.append(f"[{level_style}]{level}[/{level_style}]")
            else:
                row.append("N/A")
        
        table.add_row(*row)
    
    console.print(table)
    
    # Output to file if specified
    if output:
        output_path = Path(output)
        data = monitor.export_queries("json")
        output_path.write_text(data)
        console.print(f"[green]Results saved to {output}[/green]")


@cli.command()
@click.argument("domain")
@click.option(
    "--json", "-j",
    "output_json",
    is_flag=True,
    help="Output in JSON format",
)
def analyze(domain: str, output_json: bool):
    """
    Analyze a domain for security threats.
    
    Example: dnswatch analyze suspicious-domain.com
    """
    monitor = DNSMonitor()
    analyzer = DNSAnalyzer()
    
    console.print(f"[cyan]Analyzing {domain}...[/cyan]")
    
    # Resolve domain
    query = monitor.resolve(domain)
    
    # Analyze
    result = analyzer.analyze(query)
    
    if output_json:
        data = {
            "domain": domain,
            "is_suspicious": result.is_suspicious,
            "threat_level": result.max_threat_level.value,
            "performance_score": result.performance_score,
            "threats": [
                {
                    "type": t.threat_type.value,
                    "level": t.level.value,
                    "description": t.description,
                    "score": t.score,
                    "details": t.details,
                }
                for t in result.threats
            ],
            "recommendations": result.recommendations,
        }
        console.print_json(data)
    else:
        # Display analysis results
        if result.is_suspicious:
            console.print(Panel(
                f"[bold red]⚠️ Threats Detected[/bold red]\n\n"
                f"Threat Level: [bold]{result.max_threat_level.value.upper()}[/bold]\n"
                f"Performance Score: {result.performance_score:.1%}\n",
                title=f"🔍 Analysis: {domain}",
                border_style="red",
            ))
        else:
            console.print(Panel(
                f"[bold green]✓ No Threats Detected[/bold green]\n\n"
                f"Performance Score: {result.performance_score:.1%}\n",
                title=f"🔍 Analysis: {domain}",
                border_style="green",
            ))
        
        if result.threats:
            threats_table = Table(title="🚨 Detected Threats")
            threats_table.add_column("Type", style="cyan")
            threats_table.add_column("Level", style="bold")
            threats_table.add_column("Description", style="yellow")
            threats_table.add_column("Score", style="red")
            
            for threat in result.threats:
                level_style = {
                    ThreatLevel.LOW: "yellow",
                    ThreatLevel.MEDIUM: "orange1",
                    ThreatLevel.HIGH: "red",
                    ThreatLevel.CRITICAL: "bold red",
                }.get(threat.level, "white")
                
                threats_table.add_row(
                    threat.threat_type.value,
                    f"[{level_style}]{threat.level.value.upper()}[/{level_style}]",
                    threat.description,
                    f"{threat.score:.2f}",
                )
            
            console.print(threats_table)
        
        if result.recommendations:
            console.print("\n💡 [bold]Recommendations:[/bold]")
            for rec in result.recommendations:
                console.print(f"  • {rec}")


@cli.command()
@click.option(
    "--domains",
    "-d",
    multiple=True,
    help="Domains to monitor (can be used multiple times)",
)
@click.option(
    "--file", "-f",
    type=click.Path(exists=True),
    default=None,
    help="File containing domains to monitor (one per line)",
)
@click.option(
    "--refresh",
    "-r",
    default=1.0,
    help="Dashboard refresh rate in seconds (default: 1.0)",
)
def monitor(
    domains: List[str],
    file: Optional[str],
    refresh: float,
):
    """
    Start real-time DNS monitoring dashboard.
    
    Example: dnswatch monitor -d google.com -d github.com
    """
    # Load domains from file if provided
    domain_list = list(domains)
    if file:
        file_path = Path(file)
        file_domains = [
            line.strip()
            for line in file_path.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        domain_list.extend(file_domains)
    
    if not domain_list:
        console.print("[yellow]No domains specified. Dashboard will show empty state.[/yellow]")
        console.print("[dim]Tip: Use -d DOMAIN to specify domains to monitor.[/dim]")
    
    # Create and run dashboard
    dashboard = DNSWatchDashboard(refresh_rate=refresh)
    
    console.print("[bold blue]🔍 Starting DNSWatch Dashboard...[/bold blue]")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")
    
    try:
        dashboard.run(domain_list if domain_list else None)
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring stopped.[/yellow]")


@cli.command()
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "markdown", "html"]),
    default="markdown",
    help="Report format (default: markdown)",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Output file path",
)
def report(
    format: str,
    output: Optional[str],
):
    """
    Generate analysis report.
    
    Note: This command requires prior monitoring data.
    Use 'monitor' command first to collect data.
    """
    analyzer = DNSAnalyzer()
    
    if not analyzer._results:
        console.print("[yellow]No analysis data available.[/yellow]")
        console.print("[dim]Run 'dnswatch monitor' first to collect data.[/dim]")
        return
    
    report_content = analyzer.generate_report(format=format)
    
    if output:
        output_path = Path(output)
        output_path.write_text(report_content)
        console.print(f"[green]Report saved to {output}[/green]")
    else:
        console.print(report_content)


@cli.command()
def stats():
    """
    Show DNS statistics summary.
    
    Note: This command requires prior monitoring data.
    """
    analyzer = DNSAnalyzer()
    
    if not analyzer._results:
        console.print("[yellow]No statistics available.[/yellow]")
        console.print("[dim]Run 'dnswatch monitor' first to collect data.[/dim]")
        return
    
    stats_data = analyzer.get_statistics()
    
    # Display statistics
    table = Table(title="📊 DNS Statistics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Total Queries", str(stats_data.total_queries))
    table.add_row("Successful", f"{stats_data.successful_queries} ({stats_data.success_rate:.1%})")
    table.add_row("Failed", str(stats_data.failed_queries))
    table.add_row("Suspicious", f"{stats_data.suspicious_queries} ({stats_data.suspicious_rate:.1%})")
    table.add_row("Avg Response Time", f"{stats_data.avg_response_time_ms:.2f}ms")
    table.add_row("Min Response Time", f"{stats_data.min_response_time_ms:.2f}ms")
    table.add_row("Max Response Time", f"{stats_data.max_response_time_ms:.2f}ms")
    
    console.print(table)
    
    # Query type distribution
    if stats_data.query_types:
        type_table = Table(title="📝 Query Type Distribution")
        type_table.add_column("Type", style="cyan")
        type_table.add_column("Count", style="green")
        type_table.add_column("Percentage", style="yellow")
        
        total = sum(stats_data.query_types.values())
        for qtype, count in sorted(
            stats_data.query_types.items(),
            key=lambda x: x[1],
            reverse=True
        ):
            type_table.add_row(qtype, str(count), f"{count/total:.1%}")
        
        console.print(type_table)


def main():
    """Main entry point"""
    cli()


if __name__ == "__main__":
    main()
