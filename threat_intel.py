from collections import defaultdict, Counter
from urllib.parse import urlparse

def analyze_threat_intel(conn_logs, dns_logs, http_logs):
    alerts = []
    
    # 1. Suspicious Patterns
    # - Long duration connections
    # - High data transfer (exfiltration)
    # - One-to-many connections (scanning)
    
    def safe_float(val):
        try:
            return float(val)
        except (ValueError, TypeError):
            return 0.0

    def safe_int(val):
        try:
            return int(val)
        except (ValueError, TypeError):
            return 0

    origin_to_dest = defaultdict(set)
    dest_count = Counter()
    
    for log in conn_logs:
        duration = safe_float(log.get('duration'))
        orig_bytes = safe_int(log.get('orig_bytes'))
        resp_bytes = safe_int(log.get('resp_bytes'))
        orig_h = log.get('id.orig_h')
        resp_h = log.get('id.resp_h')
        proto = log.get('proto')
        
        if duration > 3600: # 1 hour
            alerts.append({
                "type": "Long connection", 
                "description": f"Connection from {orig_h} to {resp_h} lasted {duration}s",
                "severity": "medium",
                "source": orig_h,
                "target": resp_h
            })
            
        if orig_bytes > 10 * 1024 * 1024:  # 10MB upload in one conn
            alerts.append({
                "type": "High Data Transfer (Possible Exfiltration)", 
                "description": f"{orig_h} sent {orig_bytes} bytes to {resp_h}",
                "severity": "high",
                "source": orig_h,
                "target": resp_h
            })
            
        if orig_h and resp_h:
            origin_to_dest[orig_h].add(resp_h)
            dest_count[resp_h] += 1

    # Port scanning (one origin to many destinations)
    for orig, dests in origin_to_dest.items():
        if len(dests) > 50:
            alerts.append({
                "type": "Network Scanning",
                "description": f"{orig} connected to {len(dests)} unique destinations",
                "severity": "medium",
                "source": orig
            })

    # 3. Basic Threat Intelligence (Suspicious TLDs / domains)
    suspicious_tlds = {'.xyz', '.ru', '.cn', '.tk', '.cc', '.surf', '.top'}
    dns_query_count = Counter()
    
    for log in dns_logs:
        query = log.get('query', '')
        if query and isinstance(query, str):
            dns_query_count[query] += 1
            for tld in suspicious_tlds:
                if query.endswith(tld):
                    alerts.append({
                        "type": "Suspicious TLD",
                        "description": f"DNS query for suspicious domain: {query}",
                        "severity": "high",
                        "target": query
                    })
                    break

    for log in http_logs:
        host = log.get('host', '')
        if host and isinstance(host, str):
            for tld in suspicious_tlds:
                if host.endswith(tld):
                    alerts.append({
                        "type": "Suspicious TLD",
                        "description": f"HTTP request to suspicious domain: {host}",
                        "severity": "high",
                        "target": host
                    })
                    break

    # 4. Behavior Analysis (Beaconing)
    # Simple heuristic: excessive DNS queries for the same domain
    for query, count in dns_query_count.items():
        if count > 100:
            alerts.append({
                "type": "Possible Beaconing",
                "description": f"Domain {query} queried {count} times",
                "severity": "medium",
                "target": query
            })

    return sorted(alerts, key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x.get("severity", "low"), 3))
