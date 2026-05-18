"""
DNS Monitor Module

Core DNS monitoring functionality with query capture,
resolution, and performance tracking.
"""

import asyncio
import json
import logging
import socket
import struct
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set

from dnswatch.models import (
    DNSQuery,
    DNSRecord,
    DNSStatistics,
    QueryType,
    is_valid_domain,
)

logger = logging.getLogger(__name__)


class DNSMonitor:
    """
    DNS Query Monitor
    
    Monitors DNS queries with real-time tracking, performance analysis,
    and optional threat detection integration.
    """
    
    # Default DNS servers
    DEFAULT_NAMESERVERS = [
        "8.8.8.8",      # Google DNS
        "8.8.4.4",      # Google DNS Secondary
        "1.1.1.1",      # Cloudflare DNS
        "1.0.0.1",      # Cloudflare DNS Secondary
        "208.67.222.222",  # OpenDNS
        "208.67.220.220",  # OpenDNS Secondary
    ]
    
    # Common DNS query types
    QUERY_TYPE_MAP = {
        1: QueryType.A,
        2: QueryType.NS,
        5: QueryType.CNAME,
        6: QueryType.SOA,
        12: QueryType.PTR,
        15: QueryType.MX,
        16: QueryType.TXT,
        28: QueryType.AAAA,
        33: QueryType.SRV,
        43: QueryType.DS,
        48: QueryType.DNSKEY,
        46: QueryType.RRSIG,
        255: QueryType.ANY,
    }
    
    def __init__(
        self,
        nameservers: Optional[List[str]] = None,
        timeout: float = 5.0,
        max_workers: int = 10,
        cache_size: int = 1000,
    ):
        """
        Initialize DNS Monitor.
        
        Args:
            nameservers: List of DNS servers to use
            timeout: Query timeout in seconds
            max_workers: Maximum concurrent queries
            cache_size: Maximum cached responses
        """
        self.nameservers = nameservers or self.DEFAULT_NAMESERVERS
        self.timeout = timeout
        self.max_workers = max_workers
        self.cache_size = cache_size
        
        # Query tracking
        self._queries: List[DNSQuery] = []
        self._cache: Dict[str, DNSQuery] = {}
        self._domain_counts: Dict[str, int] = defaultdict(int)
        self._query_type_counts: Dict[str, int] = defaultdict(int)
        
        # Callbacks
        self._on_query_callbacks: List[Callable[[DNSQuery], None]] = []
        self._on_error_callbacks: List[Callable[[Exception], None]] = []
        
        # State
        self._running = False
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
    
    def add_query_callback(self, callback: Callable[[DNSQuery], None]) -> None:
        """Add callback for new queries"""
        self._on_query_callbacks.append(callback)
    
    def add_error_callback(self, callback: Callable[[Exception], None]) -> None:
        """Add callback for errors"""
        self._on_error_callbacks.append(callback)
    
    def resolve(
        self,
        domain: str,
        query_type: QueryType = QueryType.A,
        nameserver: Optional[str] = None,
    ) -> DNSQuery:
        """
        Resolve a DNS query.
        
        Args:
            domain: Domain to query
            query_type: Type of DNS query
            nameserver: Specific nameserver to use
            
        Returns:
            DNSQuery with results
        """
        if not is_valid_domain(domain):
            return DNSQuery(
                timestamp=datetime.now(),
                domain=domain,
                query_type=query_type,
                nameserver=nameserver or self.nameservers[0],
                response_time_ms=0,
                error="Invalid domain name",
            )
        
        ns = nameserver or self.nameservers[0]
        start_time = time.time()
        
        try:
            # Use socket for DNS resolution
            records = self._resolve_with_socket(domain, query_type, ns)
            response_time = (time.time() - start_time) * 1000
            
            query = DNSQuery(
                timestamp=datetime.now(),
                domain=domain,
                query_type=query_type,
                nameserver=ns,
                response_time_ms=response_time,
                records=records,
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            query = DNSQuery(
                timestamp=datetime.now(),
                domain=domain,
                query_type=query_type,
                nameserver=ns,
                response_time_ms=response_time,
                error=str(e),
            )
        
        # Track query
        self._track_query(query)
        
        # Notify callbacks
        for callback in self._on_query_callbacks:
            try:
                callback(query)
            except Exception as e:
                logger.error(f"Callback error: {e}")
        
        return query
    
    def _resolve_with_socket(
        self,
        domain: str,
        query_type: QueryType,
        nameserver: str,
    ) -> List[DNSRecord]:
        """
        Resolve DNS using raw socket.
        
        This is a simplified implementation that uses Python's
        built-in socket module for basic DNS resolution.
        """
        records = []
        
        if query_type == QueryType.A:
            # A record - IPv4 address
            try:
                info = socket.getaddrinfo(domain, None, socket.AF_INET)
                for family, _, _, _, addr in info:
                    if family == socket.AF_INET:
                        records.append(DNSRecord(
                            name=domain,
                            record_type=QueryType.A,
                            ttl=300,
                            value=addr[0],
                        ))
            except socket.gaierror:
                pass
                
        elif query_type == QueryType.AAAA:
            # AAAA record - IPv6 address
            try:
                info = socket.getaddrinfo(domain, None, socket.AF_INET6)
                for family, _, _, _, addr in info:
                    if family == socket.AF_INET6:
                        records.append(DNSRecord(
                            name=domain,
                            record_type=QueryType.AAAA,
                            ttl=300,
                            value=addr[0],
                        ))
            except socket.gaierror:
                pass
                
        elif query_type == QueryType.MX:
            # MX record - Mail exchange
            try:
                import dns.resolver
                answers = dns.resolver.resolve(domain, "MX")
                for rdata in answers:
                    records.append(DNSRecord(
                        name=domain,
                        record_type=QueryType.MX,
                        ttl=rdata.ttl if hasattr(rdata, "ttl") else 300,
                        value=str(rdata.exchange),
                        priority=rdata.preference,
                    ))
            except ImportError:
                # dnspython not available, skip MX
                pass
            except Exception:
                pass
                
        elif query_type == QueryType.CNAME:
            # CNAME record - Alias
            try:
                import dns.resolver
                answers = dns.resolver.resolve(domain, "CNAME")
                for rdata in answers:
                    records.append(DNSRecord(
                        name=domain,
                        record_type=QueryType.CNAME,
                        ttl=rdata.ttl if hasattr(rdata, "ttl") else 300,
                        value=str(rdata.target),
                    ))
            except ImportError:
                pass
            except Exception:
                pass
                
        elif query_type == QueryType.TXT:
            # TXT record
            try:
                import dns.resolver
                answers = dns.resolver.resolve(domain, "TXT")
                for rdata in answers:
                    txt_data = b"".join(rdata.strings).decode("utf-8", errors="replace")
                    records.append(DNSRecord(
                        name=domain,
                        record_type=QueryType.TXT,
                        ttl=rdata.ttl if hasattr(rdata, "ttl") else 300,
                        value=txt_data,
                    ))
            except ImportError:
                pass
            except Exception:
                pass
                
        elif query_type == QueryType.NS:
            # NS record - Nameserver
            try:
                import dns.resolver
                answers = dns.resolver.resolve(domain, "NS")
                for rdata in answers:
                    records.append(DNSRecord(
                        name=domain,
                        record_type=QueryType.NS,
                        ttl=rdata.ttl if hasattr(rdata, "ttl") else 300,
                        value=str(rdata.target),
                    ))
            except ImportError:
                pass
            except Exception:
                pass
        
        return records
    
    def _track_query(self, query: DNSQuery) -> None:
        """Track query for statistics"""
        self._queries.append(query)
        self._domain_counts[query.domain] += 1
        self._query_type_counts[query.query_type.value] += 1
        
        # Update cache
        cache_key = f"{query.domain}:{query.query_type.value}"
        if len(self._cache) >= self.cache_size:
            # Remove oldest entry
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]
        self._cache[cache_key] = query
    
    def batch_resolve(
        self,
        domains: List[str],
        query_type: QueryType = QueryType.A,
        nameserver: Optional[str] = None,
    ) -> List[DNSQuery]:
        """
        Resolve multiple domains in parallel.
        
        Args:
            domains: List of domains to resolve
            query_type: Type of DNS query
            nameserver: Specific nameserver to use
            
        Returns:
            List of DNSQuery results
        """
        futures = []
        for domain in domains:
            future = self._executor.submit(
                self.resolve, domain, query_type, nameserver
            )
            futures.append(future)
        
        results = []
        for future in futures:
            try:
                results.append(future.result(timeout=self.timeout))
            except Exception as e:
                logger.error(f"Batch resolve error: {e}")
        
        return results
    
    def get_statistics(self) -> DNSStatistics:
        """Get DNS query statistics"""
        stats = DNSStatistics()
        stats.total_queries = len(self._queries)
        
        if stats.total_queries == 0:
            return stats
        
        # Calculate success/failure rates
        response_times = []
        for query in self._queries:
            if query.is_successful:
                stats.successful_queries += 1
            else:
                stats.failed_queries += 1
            
            response_times.append(query.response_time_ms)
        
        # Response time statistics
        if response_times:
            stats.avg_response_time_ms = sum(response_times) / len(response_times)
            stats.min_response_time_ms = min(response_times)
            stats.max_response_time_ms = max(response_times)
        
        # Query type distribution
        stats.query_types = dict(self._query_type_counts)
        
        # Top domains
        sorted_domains = sorted(
            self._domain_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        stats.top_domains = sorted_domains[:20]
        
        # TLD distribution
        tld_counts: Dict[str, int] = defaultdict(int)
        for query in self._queries:
            tld = query.tld
            if tld:
                tld_counts[tld] += 1
        stats.tld_distribution = dict(tld_counts)
        
        return stats
    
    def get_queries(
        self,
        limit: Optional[int] = None,
        domain_filter: Optional[str] = None,
        type_filter: Optional[QueryType] = None,
    ) -> List[DNSQuery]:
        """
        Get tracked queries with optional filters.
        
        Args:
            limit: Maximum number of queries to return
            domain_filter: Filter by domain pattern
            type_filter: Filter by query type
            
        Returns:
            List of matching DNS queries
        """
        queries = self._queries
        
        if domain_filter:
            queries = [q for q in queries if domain_filter in q.domain]
        
        if type_filter:
            queries = [q for q in queries if q.query_type == type_filter]
        
        if limit:
            queries = queries[-limit:]
        
        return queries
    
    def clear_cache(self) -> None:
        """Clear query cache"""
        self._cache.clear()
    
    def reset_statistics(self) -> None:
        """Reset all statistics"""
        self._queries.clear()
        self._domain_counts.clear()
        self._query_type_counts.clear()
        self._cache.clear()
    
    def export_queries(self, format: str = "json") -> str:
        """
        Export queries to specified format.
        
        Args:
            format: Export format (json, csv)
            
        Returns:
            Exported data as string
        """
        if format == "json":
            data = []
            for query in self._queries:
                data.append({
                    "timestamp": query.timestamp.isoformat(),
                    "domain": query.domain,
                    "query_type": query.query_type.value,
                    "nameserver": query.nameserver,
                    "response_time_ms": query.response_time_ms,
                    "records": [
                        {
                            "name": r.name,
                            "type": r.record_type.value,
                            "ttl": r.ttl,
                            "value": r.value,
                        }
                        for r in query.records
                    ],
                    "error": query.error,
                    "is_successful": query.is_successful,
                })
            return json.dumps(data, indent=2)
        
        elif format == "csv":
            lines = [
                "timestamp,domain,query_type,nameserver,response_time_ms,error,is_successful"
            ]
            for query in self._queries:
                lines.append(
                    f"{query.timestamp.isoformat()},"
                    f"{query.domain},"
                    f"{query.query_type.value},"
                    f"{query.nameserver},"
                    f"{query.response_time_ms:.2f},"
                    f"{query.error or ''},"
                    f"{query.is_successful}"
                )
            return "\n".join(lines)
        
        raise ValueError(f"Unsupported format: {format}")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self._executor.shutdown(wait=False)
        return False
