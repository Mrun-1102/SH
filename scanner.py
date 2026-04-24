import ipaddress
import json
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from elastic import get_es, index_ip_scan, get_ip_scan
from nmap_to_json import scan_ip as build_profile

# Consistent with elastic.py
SCAN_INDEX = "ip-intelligence-latest"

_SCAN_EXECUTOR = ThreadPoolExecutor(max_workers=max(int(os.getenv("IP_INTEL_WORKERS", "4")), 1))
_SCAN_IN_FLIGHT = set()
_SCAN_IN_FLIGHT_LOCK = threading.Lock()
_SCAN_WAIT_TIMEOUT_SECONDS = float(os.getenv("IP_INTEL_WAIT_SECONDS", "12"))
_SCAN_WAIT_POLL_SECONDS = float(os.getenv("IP_INTEL_WAIT_POLL_SECONDS", "0.5"))


def _is_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(str(ip))
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except Exception:
        return False


def _can_os_fingerprint():
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid):
        try:
            return geteuid() == 0
        except Exception:
            return False
    return False

def create_scan_index():
    mapping = {
        "mappings": {
            "properties": {
                "ip": {"type": "ip"},
                "scan_time": {"type": "date"},
                "enriched_at": {"type": "date"},
                "last_seen": {"type": "date"},
                "pcap_id": {"type": "keyword"},
                "source": {"type": "keyword"},
                "os": {"type": "text"},
                "vendor": {"type": "text"},
                "status": {"type": "keyword"},
                "risk_score": {"type": "integer"},
                "rdns": {"type": "text"},
                "asn": {"type": "keyword"},
                "whois": {
                    "properties": {
                        "org": {"type": "text"},
                        "name": {"type": "text"},
                        "email": {"type": "keyword"},
                        "phone": {"type": "keyword"},
                        "technical_contact": {"type": "keyword"},
                        "registrar": {"type": "keyword"}
                    }
                },
                "geo": {
                    "properties": {
                        "country": {"type": "keyword"},
                        "city": {"type": "keyword"},
                        "isp": {"type": "text"},
                        "latitude": {"type": "double"},
                        "longitude": {"type": "double"}
                    }
                },
                "dnsbl": {
                    "properties": {
                        "status": {"type": "keyword"},
                        "listed": {"type": "boolean"},
                        "total_listings": {"type": "integer"}
                    }
                },
                "ports": {
                    "type": "nested",
                    "properties": {
                        "port": {"type": "integer"},
                        "protocol": {"type": "keyword"},
                        "state": {"type": "keyword"},
                        "service": {"type": "text"},
                        "product": {"type": "text"},
                        "version": {"type": "text"},
                        "cpe": {"type": "keyword"},
                        "http": {
                            "properties": {
                                "status": {"type": "integer"},
                                "title": {"type": "text"},
                                "server": {"type": "text"}
                            }
                        },
                        "tls": {
                            "properties": {
                                "issuer": {"type": "text"},
                                "not_after": {"type": "text"}
                            }
                        },
                        "cves": {
                            "type": "nested",
                            "properties": {
                                "id": {"type": "keyword"},
                                "score": {"type": "double"},
                                "severity": {"type": "keyword"}
                            }
                        }
                    }
                },
                "details": {
                    "properties": {
                        "os_details": {"properties": {"best_match": {"type": "text"}}}
                    }
                }
            }
        }
    }
    try:
        es_client = get_es()
        if es_client:
            if not es_client.indices.exists(index=SCAN_INDEX):
                es_client.indices.create(index=SCAN_INDEX, body=mapping)
                print(f"✓ Created Index: {SCAN_INDEX}")
    except Exception as e:
        print(f"Error creating scan index: {e}")

def get_scan_data(ip):
    return get_ip_scan(ip)

def wait_for_scan_data(ip, timeout=_SCAN_WAIT_TIMEOUT_SECONDS, poll_seconds=_SCAN_WAIT_POLL_SECONDS):
    deadline = time.time() + max(float(timeout), 0)
    while True:
        existing = get_scan_data(ip)
        if existing:
            return existing
        if time.time() >= deadline:
            return None
        time.sleep(max(float(poll_seconds), 0.1))


def _has_useful_scan(ip):
    """Check if we already have a complete intelligence profile for this IP."""
    existing = get_scan_data(ip)
    if not isinstance(existing, dict):
        return False
    if existing.get("status") == "error":
        return False
    
    # We consider a scan "useful" if it has either ports OR full enrichment
    has_ports = bool(existing.get("ports"))
    whois = existing.get("whois") or {}
    has_enrichment = bool(whois.get("org") or whois.get("asn") or existing.get("geo", {}).get("country"))
    
    return has_ports or has_enrichment


def run_nmap_scan(ip, force=False, pcap_id=None, source="manual"):
    create_scan_index()
    
    if not force:
        existing = get_scan_data(ip)
        if _has_useful_scan(ip):
            return existing

    print(f"[*] Enrolling IP {ip} for Deep Intelligence enrichment...")
    
    try:
        include_os = _can_os_fingerprint()
        profile = build_profile(
            ip, 
            top_ports=200, 
            include_scripts=True, 
            include_cves=True,
            include_os=include_os
        )
        
        details = profile.get("details", {})
        geo = profile.get("geo") or {}
        whois = profile.get("whois") or {}
        provider = details.get("service_provider") or {}
        
        scan_time = datetime.utcnow().isoformat()
        
        scan_data = {
            "ip": ip,
            "scan_time": scan_time,
            "enriched_at": scan_time,
            "last_seen": scan_time,
            "pcap_id": pcap_id,
            "source": source,
            "os": details.get("os_details", {}).get("best_match") or "Unknown",
            "vendor": provider.get("org") or whois.get("org") or geo.get("isp") or "Unknown",
            "status": "up",
            "risk_score": details.get("risk_score") or 0,
            "rdns": details.get("network", {}).get("reverse_dns") or "N/A",
            "asn": provider.get("asn") or whois.get("asn") or "N/A",
            "geo": {
                "country": geo.get("country"),
                "city": geo.get("city"),
                "isp": geo.get("isp"),
                "latitude": geo.get("latitude"),
                "longitude": geo.get("longitude")
            },
            "whois": {
                "org": provider.get("org") or whois.get("org"),
                "email": whois.get("email"),
                "phone": whois.get("phone"),
                "technical_contact": provider.get("technical_contact") or whois.get("email"),
                "registrar": provider.get("registrar") or whois.get("registrar"),
            },
            "dnsbl": profile.get("dnsbl"),
            "ports": profile.get("services", []),
            "details": details,
            "domain": profile.get("whois", {}).get("domain_whois"),
            "timing_seconds": profile.get("timing_seconds")
        }
        
        index_ip_scan(scan_data)
        print(f"✓ Deep Intelligence saved for {ip} (Score: {scan_data['risk_score']})")
        return scan_data
        
    except Exception as e:
        error_time = datetime.utcnow().isoformat()
        error_data = {
            "ip": ip,
            "scan_time": error_time,
            "enriched_at": error_time,
            "last_seen": error_time,
            "pcap_id": pcap_id,
            "source": source,
            "status": "error",
            "error": str(e),
        }
        print(f"✗ Deep scan failed for {ip}: {e}")
        index_ip_scan(error_data)
        return error_data


def _scan_and_store(ip, pcap_id=None, source="zeek_background"):
    try:
        run_nmap_scan(ip, force=True, pcap_id=pcap_id, source=source)
    finally:
        with _SCAN_IN_FLIGHT_LOCK:
            _SCAN_IN_FLIGHT.discard(str(ip))


def enqueue_ip_intelligence_scan(ip, pcap_id=None, source="zeek_background"):
    if not ip or not _is_public_ip(ip):
        return False

    create_scan_index()
    ip_key = str(ip)
    if _has_useful_scan(ip_key):
        return False
    with _SCAN_IN_FLIGHT_LOCK:
        if ip_key in _SCAN_IN_FLIGHT:
            return False
        _SCAN_IN_FLIGHT.add(ip_key)

    _SCAN_EXECUTOR.submit(_scan_and_store, ip_key, pcap_id, source)
    return True


def enqueue_ip_intelligence_scans(external_ips, pcap_id=None, source="zeek_background"):
    queued = []
    seen = set()
    for item in external_ips or []:
        ip = item.get("ip") if isinstance(item, dict) else item
        ip = str(ip).strip() if ip is not None else ""
        if not ip or ip in seen:
            continue
        seen.add(ip)
        if enqueue_ip_intelligence_scan(ip, pcap_id=pcap_id, source=source):
            queued.append(ip)
    return queued
