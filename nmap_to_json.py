#!/usr/bin/env python3

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import time
from urllib.parse import urlparse

try:
    import requests
except Exception:
    requests = None

try:
    import dns.resolver
except Exception:
    dns = None

try:
    import nmap
except Exception:
    nmap = None

try:
    from ipwhois import IPWhois
except Exception:
    IPWhois = None

try:
    import nvdlib
except Exception:
    nvdlib = None

try:
    import whois as domain_whois
except Exception:
    domain_whois = None

# -------------------------
# GEO (your existing module)
# -------------------------
try:
    from geo_ip import lookup_ip_geolocation
except ImportError:
    def lookup_ip_geolocation(ip):
        return {}

if requests is not None:
    try:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    except Exception:
        pass

HTTP_PORT_SCHEMES = {
    80: "http",
    443: "https",
    8080: "http",
    8443: "https",
}

CONTENT_TYPE_HINTS = {
    "text/html": "html",
    "text/plain": "text",
    "application/json": "json",
    "application/xml": "xml",
    "text/xml": "xml",
    "image/jpeg": "jpeg",
    "image/jpg": "jpeg",
    "image/png": "png",
    "image/gif": "gif",
    "application/pdf": "pdf",
    "application/zip": "zip",
    "application/x-gzip": "gzip",
}

NVD_API_KEY = os.getenv('NVD_API_KEY')

_APP_NMAP_SCANNER = None
_APP_NMAP_CACHE = {}
_APP_WHOIS_CACHE = {}
_APP_VULN_CACHE = {}
_APP_DOMAIN_WHOIS_CACHE = {}
_APP_DNSBL_CACHE = {}


# -------------------------
# DNS PROBE
# -------------------------
def get_dns_info(ip):
    result = {
        "reverse_dns": None,
        "answers": [],
    }

    try:
        result["reverse_dns"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    hostname = result.get("reverse_dns")
    if hostname and dns is not None:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            query = resolver.resolve(hostname, "A")
            for record in query:
                result["answers"].append(str(record))
        except Exception:
            pass

    return result


def _coerce_scalar(value):
    if isinstance(value, (list, tuple, set)):
        for item in value:
            coerced = _coerce_scalar(item)
            if coerced not in (None, '', []):
                return coerced
        return None
    if hasattr(value, 'isoformat'):
        try:
            return value.isoformat()
        except Exception:
            return str(value)
    return value


def _extract_registered_domain(hostname):
    host = str(hostname or '').strip().rstrip('.').lower()
    if not host:
        return None
    parts = [part for part in host.split('.') if part]
    if len(parts) < 2:
        return None

    common_second_level_suffixes = {
        'co.uk', 'org.uk', 'gov.uk', 'ac.uk',
        'com.au', 'net.au', 'org.au',
        'co.jp', 'ne.jp', 'or.jp',
        'co.in', 'net.in', 'org.in',
    }
    last_two = '.'.join(parts[-2:])
    last_three = '.'.join(parts[-3:]) if len(parts) >= 3 else None

    if last_three and last_two in common_second_level_suffixes:
        return last_three
    return last_two


def get_domain_whois(hostname):
    domain = _extract_registered_domain(hostname)
    if not domain or domain_whois is None:
        return {}
    if domain in _APP_DOMAIN_WHOIS_CACHE:
        return _APP_DOMAIN_WHOIS_CACHE[domain]

    try:
        raw = domain_whois.whois(domain)
        result = {
            "domain": domain,
            "registrar": _coerce_scalar(getattr(raw, 'registrar', None) if hasattr(raw, 'registrar') else raw.get('registrar')),
            "creation_date": _coerce_scalar(getattr(raw, 'creation_date', None) if hasattr(raw, 'creation_date') else raw.get('creation_date')),
            "expiration_date": _coerce_scalar(getattr(raw, 'expiration_date', None) if hasattr(raw, 'expiration_date') else raw.get('expiration_date')),
            "updated_date": _coerce_scalar(getattr(raw, 'updated_date', None) if hasattr(raw, 'updated_date') else raw.get('updated_date')),
            "name_servers": getattr(raw, 'name_servers', None) if hasattr(raw, 'name_servers') else raw.get('name_servers'),
            "emails": getattr(raw, 'emails', None) if hasattr(raw, 'emails') else raw.get('emails'),
            "org": _coerce_scalar(getattr(raw, 'org', None) if hasattr(raw, 'org') else raw.get('org')),
            "name": _coerce_scalar(getattr(raw, 'name', None) if hasattr(raw, 'name') else raw.get('name')),
            "address": _coerce_scalar(getattr(raw, 'address', None) if hasattr(raw, 'address') else raw.get('address')),
            "city": _coerce_scalar(getattr(raw, 'city', None) if hasattr(raw, 'city') else raw.get('city')),
            "state": _coerce_scalar(getattr(raw, 'state', None) if hasattr(raw, 'state') else raw.get('state')),
            "country": _coerce_scalar(getattr(raw, 'country', None) if hasattr(raw, 'country') else raw.get('country')),
            "dnssec": _coerce_scalar(getattr(raw, 'dnssec', None) if hasattr(raw, 'dnssec') else raw.get('dnssec')),
        }
        tld = domain.rsplit('.', 1)[-1].upper() if '.' in domain else None
        result["tld"] = tld
        _APP_DOMAIN_WHOIS_CACHE[domain] = result
        return result
    except Exception:
        _APP_DOMAIN_WHOIS_CACHE[domain] = {}
        return {}


# -------------------------
# HTTP PROBE
# -------------------------
def get_http_info(ip, port):
    if requests is None:
        return {}

    scheme = HTTP_PORT_SCHEMES.get(port, "http")
    port_suffix = "" if (scheme == "http" and port == 80) or (scheme == "https" and port == 443) else f":{port}"
    url = f"{scheme}://{ip}{port_suffix}"

    try:
        r = requests.get(url, timeout=(2, 4), allow_redirects=True, verify=False)
        body = r.text[:50000]

        return {
            "url": url,
            "status": r.status_code,
            "headers": dict(r.headers),
            "final_url": r.url,
            "title": extract_title(body),
            "body_hash": hashlib.sha256(body.encode(errors="ignore")).hexdigest(),
            "server": r.headers.get("Server"),
            "powered_by": r.headers.get("X-Powered-By"),
            "content_type": r.headers.get("Content-Type"),
            "file_types": guess_file_types(r.url, r.headers),
        }
    except Exception:
        return {}


def extract_title(html):
    try:
        match = re.search(r"<title>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else None
    except Exception:
        return None


def guess_file_types(url, headers):
    file_types = []
    content_type = (headers or {}).get("Content-Type", "")
    content_type_main = content_type.split(";")[0].strip().lower()
    if content_type_main in CONTENT_TYPE_HINTS:
        file_types.append(CONTENT_TYPE_HINTS[content_type_main])

    path = (urlparse(url or "").path or "").lower()
    ext_map = {
        ".html": "html",
        ".htm": "html",
        ".php": "php",
        ".asp": "asp",
        ".aspx": "aspx",
        ".jsp": "jsp",
        ".json": "json",
        ".xml": "xml",
        ".txt": "text",
        ".jpg": "jpeg",
        ".jpeg": "jpeg",
        ".png": "png",
        ".gif": "gif",
        ".pdf": "pdf",
        ".zip": "zip",
    }
    for ext, label in ext_map.items():
        if path.endswith(ext):
            file_types.append(label)
            break

    if not file_types and content_type_main:
        file_types.append(content_type_main)

    return sorted(set(file_types))


# -------------------------
# TLS PROBE
# -------------------------
def get_tls_info(ip, port=443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()

                return {
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": cert.get("subjectAltName"),
                }
    except Exception:
        return {}


# -------------------------
# NMAP SCAN
# -------------------------
def scan_ports(ip, top_ports=200, include_scripts=False, include_os=False):
    if nmap is None:
        return {"host": {}, "scaninfo": {}, "command_line": "", "arguments": []}

    scanner = nmap.PortScanner()

    args = [
        "-sT",
        "-sV",
        "--version-intensity", "5",
        "-T4",
        "--max-retries", "1",
        "--host-timeout", "60s",
        "--top-ports", str(top_ports),
    ]
    if include_scripts:
        args.append("-sC")
        # Added 'banner' and service-specific forensic scripts
        args.append("--script=ssl-cert,ssl-enum-ciphers,http-title,http-headers,banner,ssh-auth-methods,smb-os-discovery")
    if include_os:
        args.extend(["-O", "--osscan-guess"])

    data = scanner.scan(ip, arguments=" ".join(args))

    return {
        "host": data.get("scan", {}).get(ip, {}),
        "scaninfo": scanner.scaninfo(),
        "command_line": scanner.command_line(),
        "arguments": args,
    }


_CVE_CACHE = {}


def has_actual_cpe(cpe_value):
    if not cpe_value:
        return False
    cpe_str = str(cpe_value).strip()
    if not cpe_str or cpe_str in {'', 'n/a', 'unknown', 'none'}:
        return False
    if cpe_str.startswith('cpe:/') or cpe_str.startswith('cpe:2.3:'):
        return True
    return False


# -------------------------
# CVE LOOKUP
# -------------------------
def get_cves(cpe_from_nmap):
    if nvdlib is None:
        return []
    has_cpe = has_actual_cpe(cpe_from_nmap)
    if not has_cpe:
        return []
    key = str(cpe_from_nmap).strip().lower()
    if key in _CVE_CACHE:
        return _CVE_CACHE[key]
    try:
        search_kwargs = {
            'cpeName': cpe_from_nmap,
            'isVulnerable': True,
            'limit': 10,
        }
        if NVD_API_KEY:
            search_kwargs['key'] = NVD_API_KEY
        res = nvdlib.searchCVE(**search_kwargs)
        results = []
        for r in res:
            results.append({
                "id": r.id,
                "description": r.descriptions[0].value if r.descriptions else None,
                "score": r.impact.baseMetricV3.cvssV3.baseScore if r.impact and r.impact.baseMetricV3 else None,
                "severity": r.impact.baseMetricV3.cvssV3.baseSeverity if r.impact and r.impact.baseMetricV3 else None,
                "cpe_match": cpe_from_nmap,
                "matched_cpes": [str(cpe) for cpe in (getattr(r, 'cpe', None) or [])],
                "cpe_source": "nmap",
            })
        _CVE_CACHE[key] = results
        return results
    except Exception:
        _CVE_CACHE[key] = []
        return []


# -------------------------
# WHOIS
# -------------------------
def get_whois(ip):
    if IPWhois is None:
        return {}
    try:
        obj = IPWhois(ip)
        data = obj.lookup_rdap(depth=1)
        
        # Extract basic info
        result = {
            "asn": data.get("asn"),
            "org": data.get("asn_description") or data.get("network", {}).get("name"),
            "cidr": data.get("network", {}).get("cidr"),
            "network_owner": data.get("network", {}).get("name") or data.get("asn_description"),
            "name": None,
            "email": None,
            "phone": None,
            "address": None,
            "registrar": None,
            "roles": [],
            "registered": None,
            "abuse_name": None,
            "abuse_email": None,
            "abuse_address": None,
        }

        events = data.get("network", {}).get("events") or data.get("events") or []
        for event in events:
            action = str(event.get("event_action") or "").lower()
            if action in {"registration", "last changed", "last-modified"} and not result.get("registered"):
                result["registered"] = event.get("event_date")

        # Dig into entities for contacts (more aggressive extraction)
        entities = data.get("entities", [])
        for ent_id in entities:
            ent = data.get("objects", {}).get(ent_id, {})
            contact = ent.get("contact", {})
            roles = ent.get("roles") or []
            for role in roles:
                if role and role not in result["roles"]:
                    result["roles"].append(role)
            
            if not result.get("name") and contact.get("name"):
                result["name"] = contact.get("name")

            if not result.get("address"):
                address = contact.get("address")
                if isinstance(address, list):
                    joined = ", ".join(
                        item.get("value", "").strip()
                        for item in address
                        if isinstance(item, dict) and item.get("value")
                    )
                    if joined:
                        result["address"] = joined
                elif isinstance(address, str) and address.strip():
                    result["address"] = address.strip()
            
            # Extract multiple emails
            emails = contact.get("email") or []
            if isinstance(emails, list):
                for e in emails:
                    val = e.get("value") if isinstance(e, dict) else e
                    if val and not result.get("email"): result["email"] = val
            elif isinstance(emails, str):
                result["email"] = emails
            
            # Extract registrar info
            if "registrar" in (ent.get("roles") or []):
                result["registrar"] = contact.get("name")

            if "abuse" in roles:
                if contact.get("name") and not result.get("abuse_name"):
                    result["abuse_name"] = contact.get("name")
                if isinstance(emails, list):
                    for e in emails:
                        val = e.get("value") if isinstance(e, dict) else e
                        if val and not result.get("abuse_email"):
                            result["abuse_email"] = val
                elif isinstance(emails, str) and emails and not result.get("abuse_email"):
                    result["abuse_email"] = emails
                if result.get("address") and not result.get("abuse_address"):
                    result["abuse_address"] = result["address"]

        return result
    except Exception:
        return {}


def calculate_risk_score(profile):
    """Calculate a 0-100 risk score based on findings"""
    score = 0
    services = profile.get("services", [])
    dnsbl = profile.get("dnsbl", {})
    
    # +10 for each listed blacklist
    if dnsbl.get("listed"):
        score += min(40, dnsbl.get("total_listings", 0) * 10)
    
    # +15 for each service with a critical CVE
    for svc in services:
        for cve in svc.get("cves", []):
            sev = str(cve.get("severity") or "").upper()
            if sev == "CRITICAL": score += 20
            elif sev == "HIGH": score += 10
            elif sev == "MEDIUM": score += 5
            
    # +5 for dangerous ports (Telnet, RDP exposed)
    ports = [s.get("port") for s in services]
    if 23 in ports: score += 15
    if 3389 in ports: score += 10
    
    return min(100, score)


def get_os_details(scan_host):
    os_matches = scan_host.get("osmatch") or []
    os_classes = scan_host.get("osclass") or []
    if not os_matches and not os_classes:
        return {}
    best_match = os_matches[0] if os_matches else {}
    return {
        "best_match": best_match.get("name"),
        "accuracy": best_match.get("accuracy"),
        "line": best_match.get("line"),
        "osclasses": os_classes,
        "osmatches": os_matches[:3],
        "ports_used": scan_host.get("portsused", []),
    }


def get_protocols(service_refs):
    return sorted({svc.get("protocol") for svc in service_refs if svc.get("protocol")})


def get_metadata_summary(ip, geo, dns_info, whois, scan_host, service_refs, scan_result, risk_score):
    return {
        "ip": ip,
        "risk_score": risk_score,
        "hostnames": scan_host.get("hostnames", []),
        "protocols": get_protocols(service_refs),
        "geo_location": {
            "country": (geo or {}).get("country"),
            "city": (geo or {}).get("city"),
            "latitude": (geo or {}).get("latitude"),
            "longitude": (geo or {}).get("longitude"),
        },
        "service_provider": {
            "isp": (geo or {}).get("isp") or (whois or {}).get("org"),
            "org": (whois or {}).get("org") or (geo or {}).get("isp"),
            "asn": (whois or {}).get("asn") or (geo or {}).get("asn"),
            "cidr": (whois or {}).get("cidr"),
            "technical_contact": (whois or {}).get("email"),
            "registrar": (whois or {}).get("registrar"),
            "website": (whois or {}).get("website"),
            "registered_domain": (whois or {}).get("registered_domain"),
            "tld": (whois or {}).get("tld"),
        },
        "network": {
            "reverse_dns": (dns_info or {}).get("reverse_dns"),
            "dns_answers": (dns_info or {}).get("answers", []),
        },
        "os_details": get_os_details(scan_host),
        "application_file_types": sorted({
            ft
            for svc in service_refs
            for ft in (svc.get("http") or {}).get("file_types", [])
        }),
        "other_metadata": {
            "scan_command": (scan_result or {}).get("command_line"),
            "status_reason": (scan_host.get("status") or {}).get("reason") if isinstance(scan_host.get("status"), dict) else None,
        },
    }


def dnsbl_check(ip):
    """
    Perform a DNSBL check using dnspython (dns.resolver).
    This is preferred over pydnsbl/aiodns/pycares because the latter 
    causes fatal interpreter crashes on newer Python versions (3.12-3.14) 
    due to CFFI/GC race conditions in pycares.
    """
    if ip in _APP_DNSBL_CACHE:
        return _APP_DNSBL_CACHE[ip]
    
    if dns is None:
        return {'status': 'dns_unavailable', 'listed': None, 'total_listings': 0, 'providers': []}

    # Common stable providers
    providers_to_check = [
        'zen.spamhaus.org', 'bl.spamcop.net', 'b.barracudacentral.org', 
        'dnsbl.sorbs.net', 'spam.dnsbl.sorbs.net', 'cbl.abuseat.org', 
        'all.s5h.net', 'z.mailspike.net', 'psbl.surriel.com', 'db.wpbl.info',
        'bl.nordspam.com', 'blacklist.woody.ch', 'combined.abuse.ch'
    ]
    
    try:
        rev_ip = ".".join(reversed(ip.split(".")))
    except Exception:
        return {'status': 'invalid_ip', 'listed': None, 'total_listings': 0, 'providers': []}

    detected_by = []
    
    # We use a small local resolver for speed
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.0     # Short timeout for each
    resolver.lifetime = 1.0
    
    # Since this is already called in a thread pool from scan_ip, 
    # we can do it sequentially here to keep it simple, 
    # or use another small pool if we want to check many more.
    for host in providers_to_check:
        try:
            query = f"{rev_ip}.{host}"
            answer = resolver.resolve(query, 'A')
            if answer:
                detected_by.append({'provider': host, 'response': str(answer[0])})
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except Exception:
            continue
            
    result = {
        'status': 'ok', 
        'listed': len(detected_by) > 0, 
        'total_listings': len(detected_by), 
        'providers': detected_by
    }
    
    _APP_DNSBL_CACHE[ip] = result
    return result


# -------------------------
# MAIN PROFILE BUILDER
# -------------------------
def scan_ip(ip, top_ports=200, include_scripts=False, include_cves=True, max_cve_lookups=5, include_os=False):
    t0 = time.perf_counter()

    with ThreadPoolExecutor(max_workers=5) as pool:
        future_geo = pool.submit(lookup_ip_geolocation, ip)
        future_dns = pool.submit(get_dns_info, ip)
        future_whois = pool.submit(get_whois, ip)
        future_scan = pool.submit(scan_ports, ip, top_ports, include_scripts, include_os)
        future_dnsbl = pool.submit(dnsbl_check, ip)

        geo = future_geo.result()
        dns_info = future_dns.result()
        whois = future_whois.result()
        scan_result = future_scan.result()
        dnsbl = future_dnsbl.result()

    domain_profile = get_domain_whois((dns_info or {}).get("reverse_dns"))
    if domain_profile:
        whois = {
            **(whois or {}),
            "website": domain_profile.get("domain"),
            "registered_domain": domain_profile.get("domain"),
            "tld": domain_profile.get("tld"),
            "registrar": (whois or {}).get("registrar") or domain_profile.get("registrar"),
            "registered": (whois or {}).get("registered") or domain_profile.get("creation_date"),
            "name": (whois or {}).get("name") or domain_profile.get("name"),
            "address": (whois or {}).get("address") or ", ".join(
                [str(part) for part in [domain_profile.get("address"), domain_profile.get("city"), domain_profile.get("state"), domain_profile.get("country")] if part]
            ) or (whois or {}).get("address"),
            "org": (whois or {}).get("org") or domain_profile.get("org"),
            "domain_whois": domain_profile,
        }

    profile = {
        "ip": ip,
        "geo": geo,
        "dns": dns_info,
        "whois": whois,
        "dnsbl": dnsbl,
        "scan": {
            "command_line": scan_result.get("command_line"),
            "scaninfo": scan_result.get("scaninfo"),
            "arguments": scan_result.get("arguments"),
        },
        "services": [],
    }

    scan = scan_result.get("host") or {}
    service_refs = []

    for proto in ("tcp", "udp"):
        for port, d in (scan.get(proto) or {}).items():
            service = {
                "port": port,
                "protocol": proto,
                "service": d.get("name"),
                "product": d.get("product"),
                "version": d.get("version"),
                "state": d.get("state"),
                "reason": d.get("reason"),
                "cpe": d.get("cpe"),
                "cves": [],
                "scripts": d.get("script", {}),
            }
            if d.get("name"):
                service["application"] = d.get("name")
            profile["services"].append(service)
            service_refs.append(service)

    with ThreadPoolExecutor(max_workers=6) as pool:
        http_jobs = {}
        tls_jobs = {}
        for svc in service_refs:
            port = int(svc.get("port"))
            if port in HTTP_PORT_SCHEMES:
                http_jobs[pool.submit(get_http_info, ip, port)] = svc
            if port in (443, 8443):
                tls_jobs[pool.submit(get_tls_info, ip, port)] = svc

        for future in as_completed(http_jobs):
            svc = http_jobs[future]
            try: svc["http"] = future.result() or {}
            except Exception: svc["http"] = {}

        for future in as_completed(tls_jobs):
            svc = tls_jobs[future]
            try: svc["tls"] = future.result() or {}
            except Exception: svc["tls"] = {}

    if include_cves:
        looked_up = 0
        seen_queries = set()
        for svc in service_refs:
            if looked_up >= max_cve_lookups: break
            cpe_from_nmap = svc.get("cpe")
            query_key = str(cpe_from_nmap or '').strip().lower()
            if not query_key or query_key in seen_queries: continue
            seen_queries.add(query_key)
            svc["cves"] = get_cves(cpe_from_nmap)
            looked_up += 1

    risk_score = calculate_risk_score(profile)
    profile["details"] = get_metadata_summary(ip, geo, dns_info, whois, scan, service_refs, scan_result, risk_score)
    profile["timing_seconds"] = round(time.perf_counter() - t0, 3)
    profile["service_count"] = len(service_refs)

    return profile


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python nmap_to_json.py <IP>")
    else:
        print(json.dumps(scan_ip(sys.argv[1]), indent=2))
