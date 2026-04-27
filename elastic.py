import os
import json
import math
from datetime import datetime, timezone
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError
from elasticsearch.helpers import bulk

# ---------------- CONFIG ----------------
ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_API_KEY = os.getenv("ELASTIC_API_KEY")
ES_USER = os.getenv("ELASTIC_USER")
ES_PASSWORD = os.getenv("ELASTIC_PASSWORD")

# Granular Indexes
PCAP_CAPTURES_INDEX = "pcap-captures"  # Metadata summary
PCAP_IPS_INDEX = "pcap-ips"            # Granular IP records
PCAP_DNS_INDEX = "pcap-dns"            # Granular DNS/URL records
PCAP_PAYLOADS_INDEX = "pcap-payloads"  # Granular file/payload records
PCAP_DASHBOARD_INDEX = "pcap-dashboard"  # Full dashboard payload

# Legacy Index (for reference/compatibility)
PCAP_INDEX = "pcap-analysis"
SCAN_INDEX = "ip-intelligence-latest"
SCAN_INDEX_LEGACY = "ip-scan-results"

# ---------------- CONNECTION ----------------
_es_instance = None

def get_es():
    global _es_instance
    if _es_instance is not None:
        return _es_instance

    try:
        auth = None
        if ES_API_KEY:
            auth = {"api_key": ES_API_KEY}
        elif ES_USER and ES_PASSWORD:
            auth = (ES_USER, ES_PASSWORD)

        es = Elasticsearch(
            ES_HOST,
            basic_auth=auth if isinstance(auth, tuple) else None,
            api_key=auth["api_key"] if isinstance(auth, dict) else None,
            verify_certs=False,
            request_timeout=60,
            max_retries=3,
            retry_on_timeout=True
        )

        if es.ping():
            _es_instance = es
        else:
            _es_instance = None
    except Exception as e:
        print(f"✗ ES connection error: {e}")
        _es_instance = None

    return _es_instance

# ---------------- INDEX CREATION ----------------
def _create_index_safely(index_name, mapping):
    es = get_es()
    if es and not es.indices.exists(index=index_name):
        es.indices.create(index=index_name, body=mapping)
        print(f"✓ Created Index: {index_name}")

def create_granular_indexes():
    es = get_es()
    if not es: return

    dashboard_mapping = {
        "mappings": {
            "properties": {
                "file_id": {"type": "keyword"},
                "file_name": {"type": "keyword"},
                "analysis_timestamp": {"type": "date"},
                "start_time_utc": {"type": "date"},
                "end_time_utc": {"type": "date"},
                "duration_seconds": {"type": "double"},
                "attack_duration_seconds": {"type": "double"},
                "total_packets": {"type": "long"},
                "total_connections": {"type": "long"},
                "exact_pcap_packets": {"type": "long"},
                "total_dns_queries": {"type": "long"},
                "total_http_requests": {"type": "long"},
                "total_bytes": {"type": "long"},
                "malware_type": {"type": "keyword"},
                "infected_host": {"type": "keyword"},
                "reputation_status": {"type": "keyword"},
                "unique_sources": {"type": "long"},
                "transport_breakdown": {
                    "properties": {
                        "label": {"type": "keyword"},
                        "value": {"type": "long"}
                    }
                },
                "application_breakdown": {
                    "properties": {
                        "label": {"type": "keyword"},
                        "value": {"type": "long"}
                    }
                },
                "direction_breakdown": {
                    "properties": {
                        "label": {"type": "keyword"},
                        "value": {"type": "long"}
                    }
                },
                "dns_breakdown": {
                    "properties": {
                        "label": {"type": "keyword"},
                        "value": {"type": "long"}
                    }
                },
                "dns_domains": {
                    "properties": {
                        "label": {"type": "keyword"},
                        "value": {"type": "long"}
                    }
                },
                "url_domains": {
                    "properties": {
                        "label": {"type": "keyword"},
                        "value": {"type": "long"}
                    }
                },
                "ssl_servers": {
                    "properties": {
                        "label": {"type": "keyword"},
                        "value": {"type": "long"}
                    }
                },
                "destinations": {
                    "properties": {
                        "label": {"type": "keyword"},
                        "value": {"type": "long"}
                    }
                },
                "top_dns_domains": {
                    "properties": {
                        "label": {"type": "keyword"},
                        "value": {"type": "long"}
                    }
                },
                "top_url_domains": {
                    "properties": {
                        "label": {"type": "keyword"},
                        "value": {"type": "long"}
                    }
                },
                "top_ssl_servers": {
                    "properties": {
                        "label": {"type": "keyword"},
                        "value": {"type": "long"}
                    }
                },
                "top_destinations": {
                    "properties": {
                        "label": {"type": "keyword"},
                        "value": {"type": "long"}
                    }
                },
                "time_series": {
                    "properties": {
                        "label": {"type": "keyword"},
                        "value": {"type": "long"}
                    }
                },
                "recent_connections": {
                    "properties": {
                        "ts": {"type": "date"},
                        "uid": {"type": "keyword"},
                        "id": {
                            "properties": {
                                "orig_h": {"type": "ip"},
                                "orig_p": {"type": "integer"},
                                "resp_h": {"type": "ip"},
                                "resp_p": {"type": "integer"}
                            }
                        },
                        "proto": {"type": "keyword"},
                        "service": {"type": "keyword"},
                        "duration": {"type": "double"},
                        "orig_bytes": {"type": "long"},
                        "resp_bytes": {"type": "long"},
                        "orig_pkts": {"type": "long"},
                        "resp_pkts": {"type": "long"},
                        "orig_ip_bytes": {"type": "long"},
                        "resp_ip_bytes": {"type": "long"},
                        "conn_state": {"type": "keyword"},
                        "history": {"type": "keyword"},
                        "local_orig": {"type": "keyword"},
                        "local_resp": {"type": "keyword"},
                        "missed_bytes": {"type": "long"},
                        "ip_proto": {"type": "integer"}
                    }
                },
                "external_ips": {
                    "properties": {
                        "ip": {"type": "ip"},
                        "packet_count": {"type": "long"},
                        "country": {"type": "keyword"},
                        "city": {"type": "keyword"},
                        "latitude": {"type": "double"},
                        "longitude": {"type": "double"},
                        "isp": {"type": "keyword"},
                        "internal_ips": {
                            "properties": {
                                "ip": {"type": "ip"},
                                "packet_count": {"type": "long"}
                            }
                        }
                    }
                },
                "internal_ips": {
                    "properties": {
                        "ip": {"type": "ip"},
                        "packet_count": {"type": "long"},
                        "remarks": {"type": "keyword"}
                    }
                },
                "dns_queries": {
                    "properties": {
                        "domain": {"type": "keyword"},
                        "record_type": {"type": "keyword"},
                        "timestamp": {"type": "date"}
                    }
                },
                "ioc_ips": {
                    "properties": {
                        "ip": {"type": "ip"},
                        "reason": {"type": "keyword"}
                    }
                },
                "ioc_domains": {
                    "properties": {
                        "domain": {"type": "keyword"},
                        "reason": {"type": "keyword"}
                    }
                },
                "ioc_urls": {
                    "properties": {
                        "url": {"type": "keyword"},
                        "method": {"type": "keyword"},
                        "purpose": {"type": "keyword"}
                    }
                },
                "protocols": {
                    "properties": {
                        "protocol": {"type": "keyword"},
                        "packet_count": {"type": "long"}
                    }
                },
                "ports": {
                    "properties": {
                        "port": {"type": "keyword"},
                        "protocol": {"type": "keyword"},
                        "usage": {"type": "long"}
                    }
                },
                "user_agents": {
                    "properties": {
                        "user_agent": {"type": "keyword"}
                    }
                },
                "file_payloads": {
                    "properties": {
                        "filename": {"type": "keyword"},
                        "type": {"type": "keyword"},
                        "protocol": {"type": "keyword"},
                        "destination_ip": {"type": "ip"}
                    }
                },
                "ftp_session": {
                    "properties": {
                        "source_ip": {"type": "ip"},
                        "destination_ip": {"type": "ip"},
                        "port": {"type": "keyword"},
                        "server_banner": {"type": "text"},
                        "username": {"type": "keyword"},
                        "password": {"type": "keyword"},
                        "command": {"type": "keyword"},
                        "file_transferred": {"type": "keyword"},
                        "data_channel": {"type": "keyword"},
                        "data_type": {"type": "keyword"}
                    }
                },
                "alerts": {
                    "properties": {
                        "type": {"type": "keyword"},
                        "description": {"type": "text"},
                        "severity": {"type": "keyword"},
                        "source": {"type": "ip"},
                        "target": {"type": "ip"}
                    }
                },
                "raw_external_ips": {
                    "properties": {
                        "ip": {"type": "ip"},
                        "packet_count": {"type": "long"},
                        "country": {"type": "keyword"},
                        "city": {"type": "keyword"},
                        "latitude": {"type": "double"},
                        "longitude": {"type": "double"},
                        "isp": {"type": "keyword"}
                    }
                },
                "summary": {
                    "properties": {
                        "unique_sources": {"type": "long"},
                        "log_types": {"type": "keyword"},
                        "file_size": {"type": "long"}
                    }
                }
            },
            "dynamic": True
        }
    }

    # 1. CAPTURES SUMMARY
    captures_mapping = {
        "mappings": {
            "properties": {
                "pcap_id": {"type": "keyword"},
                "pcap_filename": {"type": "keyword"},
                "analysis_timestamp": {"type": "date"},
                "traffic_start": {"type": "date"},
                "traffic_end": {"type": "date"},
                "total_packets": {"type": "long"},
                "duration_seconds": {"type": "double"},
                "total_bytes": {"type": "long"},
                "file_size": {"type": "long"},
                "unique_ips": {"type": "integer"},
                "unique_domains": {"type": "integer"}
            }
        }
    }

    # 2. GRANULAR IPS
    ips_mapping = {
        "mappings": {
            "properties": {
                "pcap_id": {"type": "keyword"},
                "ip": {"type": "ip"},
                "packet_count": {"type": "integer"},
                "country": {"type": "keyword"},
                "city": {"type": "keyword"},
                "isp": {"type": "keyword"},
                "latitude": {"type": "double"},
                "longitude": {"type": "double"},
                "location": {"type": "geo_point"},
                "is_internal": {"type": "boolean"},
                "internal_connection_count": {"type": "integer"}
            }
        }
    }

    # 3. GRANULAR DNS/URLS
    dns_mapping = {
        "mappings": {
            "properties": {
                "pcap_id": {"type": "keyword"},
                "domain": {"type": "keyword"},
                "type": {"type": "keyword"}, # 'dns' or 'http'
                "count": {"type": "integer"},
                "is_ioc": {"type": "boolean"}
            }
        }
    }

    # 4. PAYLOADS
    payloads_mapping = {
        "mappings": {
            "properties": {
                "pcap_id": {"type": "keyword"},
                "filename": {"type": "keyword"},
                "type": {"type": "keyword"},
                "protocol": {"type": "keyword"},
                "destination_ip": {"type": "ip"}
            }
        }
    }

    _create_index_safely(PCAP_CAPTURES_INDEX, captures_mapping)
    _create_index_safely(PCAP_IPS_INDEX, ips_mapping)
    _create_index_safely(PCAP_DNS_INDEX, dns_mapping)
    _create_index_safely(PCAP_PAYLOADS_INDEX, payloads_mapping)
    _create_index_safely(PCAP_DASHBOARD_INDEX, dashboard_mapping)

def create_pcap_index():
    # Keep original for compatibility but prioritize granular
    create_granular_indexes()
    es = get_es()
    if not es: return
    if not es.indices.exists(index=PCAP_INDEX):
        mapping = {
            "mappings": {
                "properties": {
                    "pcap_id": {"type": "keyword"},
                    "pcap_filename": {"type": "keyword"},
                    "external_ips": {"type": "nested"} # Keep simplified version
                }
            }
        }
        es.indices.create(index=PCAP_INDEX, body=mapping)

# ---------------- INDEXING ----------------

def bulk_index_granular_data(pcap_id, pcap_filename, summary_data, ips_data, dns_data, payloads_data=[]):
    es = get_es()
    if not es: return
    
    # 0. Cleanup old records for this PCAP to prevent duplication
    try:
        es.delete_by_query(index=PCAP_PAYLOADS_INDEX, body={"query": {"term": {"pcap_id": pcap_id}}})
    except: pass

    actions = []

    # 1. Summary Record
    summary_data['pcap_id'] = pcap_id
    summary_data['pcap_filename'] = pcap_filename
    summary_data['analysis_timestamp'] = datetime.now(timezone.utc).isoformat()
    actions.append({
        "_index": PCAP_CAPTURES_INDEX,
        "_id": pcap_id,
        "_source": summary_data
    })

    # 2. IP Records
    for ip_record in ips_data:
        ip_record['pcap_id'] = pcap_id
        # Ensure location
        lat = ip_record.get('latitude')
        lon = ip_record.get('longitude')
        if lat is not None and lon is not None:
            ip_record['location'] = {"lat": lat, "lon": lon}
            
        actions.append({
            "_index": PCAP_IPS_INDEX,
            "_source": ip_record
        })

    # 3. DNS/URL Records
    for dns_record in dns_data:
        dns_record['pcap_id'] = pcap_id
        actions.append({
            "_index": PCAP_DNS_INDEX,
            "_source": dns_record
        })

    # 4. Payload Records
    for payload_record in payloads_data:
        payload_record['pcap_id'] = pcap_id
        actions.append({
            "_index": PCAP_PAYLOADS_INDEX,
            "_source": payload_record
        })

    try:
        # Use raise_on_error=False so that we index what we can even if some records fail
        success, errors = bulk(es, actions, raise_on_error=False)
        if errors:
            print(f"  ⚠ {len(errors)} records failed to index for {pcap_id}")
            # Debug first error
            print(f"  Sample Error: {errors[0]['index']['error']}")
        return success
    except Exception as e:
        print(f"✗ Bulk indexing error: {e}")
        return 0


def index_dashboard_document(pcap_id, dashboard_data):
    es = get_es()
    if not es:
        return None

    payload = dict(dashboard_data)
    payload["file_id"] = pcap_id
    payload["pcap_id"] = pcap_id
    payload["analysis_timestamp"] = datetime.now(timezone.utc).isoformat()

    try:
        return es.index(index=PCAP_DASHBOARD_INDEX, id=pcap_id, document=payload)
    except TypeError:
        return es.index(index=PCAP_DASHBOARD_INDEX, id=pcap_id, body=payload)
    except Exception as e:
        print(f"✗ Dashboard index error for {pcap_id}: {e}")
        return None


def get_dashboard_document(pcap_id):
    es = get_es()
    if not es:
        return None

    try:
        doc = es.get(index=PCAP_DASHBOARD_INDEX, id=pcap_id)["_source"]
        if doc.get("file_id") == pcap_id or doc.get("pcap_id") == pcap_id:
            return doc
    except NotFoundError:
        pass
    except Exception:
        pass

    try:
        res = es.search(
            index=PCAP_DASHBOARD_INDEX,
            body={"query": {"term": {"file_id": pcap_id}}},
            size=1,
        )
        hits = res.get("hits", {}).get("hits", [])
        if hits:
            doc = hits[0].get("_source", {})
            if doc.get("file_id") == pcap_id or doc.get("pcap_id") == pcap_id:
                return doc
    except Exception:
        pass

    return None


def get_latest_dashboard_document():
    es = get_es()
    if not es:
        return None

    try:
        res = es.search(
            index=PCAP_DASHBOARD_INDEX,
            body={"query": {"match_all": {}}},
            size=1,
            sort=[{"analysis_timestamp": {"order": "desc"}}]
        )
        hits = res.get("hits", {}).get("hits", [])
        if hits:
            return hits[0].get("_source")
        return None
    except Exception:
        return None

# (Legacy support for index_pcap_analysis)
def index_pcap_analysis(pcap_id, pcap_filename, external_ips, **kwargs):
    # This now just routes to granular if needed, but we should call 
    # bulk_index_granular_data directly from zeek_analysis
    pass

# ---------------- SEARCH & AGGREGATIONS ----------------

def get_pcap_stats_from_es(pcap_id):
    es = get_es()
    if not es: return None
    
    summary = get_pcap_summary(pcap_id)
    if not summary:
        return None

    # Initialize variables that will be used later
    flow = []
    geo = {'countries': []}

    # Aggr 1: Transport & Application (from zeek-conn)
    app_stats = []
    trans_stats = []
    dir_stats = []
    try:
        aggs = {
            "apps": {"terms": {"field": "service.keyword", "size": 10}},
            "trans": {"terms": {"field": "proto.keyword", "size": 10}},
            "dirs": {"terms": {"field": "direction.keyword", "size": 5}}
        }
        res = es.search(index="zeek-conn", body={
            "query": {"term": {"pcap_id": pcap_id}},
            "aggs": aggs, "size": 0
        })
        buckets = res.get("aggregations", {})
        app_stats = [{"label": b["key"] or "unknown", "value": b["doc_count"]} for b in buckets.get("apps", {}).get("buckets", [])]
        trans_stats = [{"label": b["key"], "value": b["doc_count"]} for b in buckets.get("trans", {}).get("buckets", [])]
        dir_stats = [{"label": b["key"], "value": b["doc_count"]} for b in buckets.get("dirs", {}).get("buckets", [])]
    except Exception: pass

    # Aggr 2: DNS Domains (from zeek-dns)
    dns_stats = []
    try:
        res = es.search(index="zeek-dns", body={
            "query": {"term": {"pcap_id": pcap_id}},
            "aggs": {"domains": {"terms": {"field": "query.keyword", "size": 10}}}, "size": 0
        })
        dns_stats = [{"label": b["key"], "value": b["doc_count"]} for b in res.get("aggregations", {}).get("domains", {}).get("buckets", [])]
    except Exception: pass

    # Aggr 3: External IPs (Top 100 detailed records)
    ext_ips = []
    try:
        res = es.search(index="pcap-ips", body={
            "query": {"term": {"pcap_id": pcap_id}},
            "size": 100, "sort": [{"packet_count": "desc"}]
        })
        ext_ips = [h["_source"] for h in res["hits"]["hits"]]
    except Exception: pass

    # Aggr 4: DNS Queries (Top 100 records)
    dns_records = []
    try:
        res = es.search(index="zeek-dns", body={
            "query": {"term": {"pcap_id": pcap_id}},
            "size": 100, "sort": [{"@timestamp": "desc"}]
        })
        for h in res["hits"]["hits"]:
            s = h["_source"]
            dns_records.append({
                "domain": s.get("query"),
                "record_type": s.get("qtype_name"),
                "timestamp": s.get("@timestamp")
            })
    except Exception: pass

    # Aggr 5: Protocols & Ports (from zeek-conn)
    protocols = []
    ports = []
    try:
        # We reuse the trans_stats and app_stats from above mixed with some logic
        protocols = [{"protocol": s["label"], "packet_count": s["value"]} for s in trans_stats]
        # For ports, we need another aggregation
        res = es.search(index="zeek-conn", body={
            "query": {"term": {"pcap_id": pcap_id}},
            "aggs": {
                "p": {"terms": {"field": "id.resp_p", "size": 20}, 
                      "aggs": {"pr": {"terms": {"field": "proto.keyword", "size": 1}}}}
            }, "size": 0
        })
        for b in res.get("aggregations", {}).get("p", {}).get("buckets", []):
            proto_name = b.get("pr", {}).get("buckets", [{}])[0].get("key", "unk")
            ports.append({"port": b["key"], "protocol": proto_name, "usage": b["doc_count"]})
    except Exception: pass

    stats = {
        'file_id': pcap_id,
        'file_name': summary.get('pcap_filename'),
        'total_packets': summary.get('total_packets', 0),
        'total_bytes': summary.get('total_bytes', 0),
        'duration_seconds': summary.get('duration_seconds', 0),
        'file_size': summary.get('file_size', 0),
        'total_connections': sum(s['value'] for s in trans_stats),
        'exact_pcap_packets': summary.get('total_packets'),
        'transport_breakdown': trans_stats,
        'application_breakdown': app_stats,
        'direction_breakdown': dir_stats,
        'top_dns_domains': dns_stats,
        'top_destinations': geo.get('countries', [])[:10],
        'external_ips': ext_ips,
        'internal_ips': [],
        'dns_queries': dns_records,
        'protocols': protocols,
        'ports': ports,
        'summary': summary
    }
    return stats


def get_all_pcap_summaries():
    es = get_es()
    if not es: return []
    try:
        res = es.search(
            index=PCAP_CAPTURES_INDEX,
            body={"query": {"match_all": {}}},
            size=1000,
            sort=[{"analysis_timestamp": {"order": "desc"}}]
        )
        return [hit["_source"] for hit in res["hits"]["hits"]]
    except Exception:
        return []

def get_pcap_summary(pcap_id):
    es = get_es()
    if not es: return None
    try:
        return es.get(index=PCAP_CAPTURES_INDEX, id=pcap_id)["_source"]
    except NotFoundError:
        return None


def get_repository_stats():
    es = get_es()
    if not es:
        return {
            "total_pcaps": 0,
            "observed_ips": 0,
            "repository_size": 0,
            "traffic_volume": 0,
        }

    try:
        total_pcaps = int(es.count(index=PCAP_CAPTURES_INDEX, body={"query": {"match_all": {}}}).get("count", 0))
    except Exception:
        total_pcaps = 0

    try:
        capture_agg = es.search(
            index=PCAP_CAPTURES_INDEX,
            body={
                "query": {"match_all": {}},
                "size": 0,
                "aggs": {
                    "repository_size": {"sum": {"field": "file_size"}},
                    "traffic_volume": {"sum": {"field": "total_packets"}},
                },
            },
        )
        aggs = capture_agg.get("aggregations", {})
        repository_size = int(aggs.get("repository_size", {}).get("value", 0) or 0)
        traffic_volume = int(aggs.get("traffic_volume", {}).get("value", 0) or 0)
    except Exception:
        repository_size = 0
        traffic_volume = 0

    try:
        ips_agg = es.search(
            index=PCAP_IPS_INDEX,
            body={
                "query": {"match_all": {}},
                "size": 0,
                "aggs": {
                    "observed_ips": {
                        "cardinality": {
                            "field": "ip",
                            "precision_threshold": 4000,
                        }
                    }
                },
            },
        )
        observed_ips = int(
            ips_agg.get("aggregations", {})
            .get("observed_ips", {})
            .get("value", 0)
            or 0
        )
    except Exception:
        observed_ips = 0

    return {
        "total_pcaps": total_pcaps,
        "observed_ips": observed_ips,
        "repository_size": repository_size,
        "traffic_volume": traffic_volume,
    }

def get_global_aggregation():
    es = get_es()
    if not es:
        return {
            "total_external_ips": 0,
            "total_internal_ips": 0,
            "total_bytes": 0,
            "total_packets": 0,
            "total_infected_hosts": 0,
            "total_dns_domains": 0,
            "total_url_domains": 0,
            "total_protocols": 0,
            "top_dns_domains": [],
            "top_url_domains": [],
            "top_active_ips": [],
            "protocol_breakdown": []
        }

    stats = {
        "total_external_ips": 0,
        "total_internal_ips": 0,
        "total_bytes": 0,
        "total_packets": 0,
        "total_infected_hosts": 0,
        "total_dns_domains": 0,
        "total_url_domains": 0,
        "total_protocols": 0,
        "top_dns_domains": [],
        "top_url_domains": [],
        "top_active_ips": [],
        "protocol_breakdown": []
    }

    try:
        # Agg 1: Total Bytes, Packets, and Infected Hosts
        res = es.search(
            index=PCAP_CAPTURES_INDEX,
            body={
                "size": 0,
                "aggs": {
                    "total_bytes": {"sum": {"field": "total_bytes"}},
                    "total_packets": {"sum": {"field": "total_packets"}}
                }
            }
        )
        aggs = res.get("aggregations", {})
        stats["total_bytes"] = int(aggs.get("total_bytes", {}).get("value", 0))
        stats["total_packets"] = int(aggs.get("total_packets", {}).get("value", 0))
        
        # Infected Hosts (from Dashboard index)
        # We use .keyword for aggregation on text fields and exclude "Unknown"
        res_infected = es.search(
            index=PCAP_DASHBOARD_INDEX,
            body={
                "size": 0,
                "query": {
                    "bool": {
                        "must_not": [
                            {"term": {"infected_host.keyword": "Unknown"}}
                        ]
                    }
                },
                "aggs": {"infected": {"cardinality": {"field": "infected_host.keyword"}}}
            }
        )
        stats["total_infected_hosts"] = int(res_infected.get("aggregations", {}).get("infected", {}).get("value", 0))

    except Exception: pass

    try:
        # Agg 2: Total IPs (External/Internal)
        res = es.search(
            index=PCAP_IPS_INDEX,
            body={
                "size": 0,
                "aggs": {
                    "external_count": {
                        "filter": {"term": {"is_internal": False}},
                        "aggs": {"unique": {"cardinality": {"field": "ip"}}}
                    },
                    "internal_count": {
                        "filter": {"term": {"is_internal": True}},
                        "aggs": {"unique": {"cardinality": {"field": "ip"}}}
                    },
                    "top_active": {
                        "terms": {"field": "ip", "size": 10, "order": {"total_packets": "desc"}},
                        "aggs": {"total_packets": {"sum": {"field": "packet_count"}}}
                    }
                }
            }
        )
        aggs = res.get("aggregations", {})
        stats["total_external_ips"] = int(aggs.get("external_count", {}).get("unique", {}).get("value", 0))
        stats["total_internal_ips"] = int(aggs.get("internal_count", {}).get("unique", {}).get("value", 0))
        
        buckets = aggs.get("top_active", {}).get("buckets", [])
        stats["top_active_ips"] = [{"ip": b["key"], "packets": int(b.get("total_packets", {}).get("value", 0))} for b in buckets]
    except Exception: pass

    try:
        # Agg 3: DNS and URL Domains
        res = es.search(
            index=PCAP_DNS_INDEX,
            body={
                "size": 0,
                "aggs": {
                    "dns_stats": {
                        "filter": {"term": {"type": "dns"}},
                        "aggs": {
                            "total": {"cardinality": {"field": "domain"}},
                            "top": {
                                "terms": {"field": "domain", "size": 5, "order": {"total_count": "desc"}},
                                "aggs": {"total_count": {"sum": {"field": "count"}}}
                            }
                        }
                    },
                    "url_stats": {
                        "filter": {"term": {"type": "http"}},
                        "aggs": {
                            "total": {"cardinality": {"field": "domain"}},
                            "top": {
                                "terms": {"field": "domain", "size": 5, "order": {"total_count": "desc"}},
                                "aggs": {"total_count": {"sum": {"field": "count"}}}
                            }
                        }
                    }
                }
            }
        )
        aggs = res.get("aggregations", {})
        
        # DNS
        dns_agg = aggs.get("dns_stats", {})
        stats["total_dns_domains"] = int(dns_agg.get("total", {}).get("value", 0))
        stats["top_dns_domains"] = [{"domain": b["key"], "count": int(b.get("total_count", {}).get("value", 0))} for b in dns_agg.get("top", {}).get("buckets", [])]
        
        # URL
        url_agg = aggs.get("url_stats", {})
        stats["total_url_domains"] = int(url_agg.get("total", {}).get("value", 0))
        stats["top_url_domains"] = [{"domain": b["key"], "count": int(b.get("total_count", {}).get("value", 0))} for b in url_agg.get("top", {}).get("buckets", [])]
        
    except Exception: pass

    try:
        # Agg 4: Protocols
        res = es.search(
            index="zeek-conn",
            body={
                "size": 0,
                "aggs": {
                    "total_protos": {"cardinality": {"field": "proto.keyword"}},
                    "protocols": {
                        "terms": {"field": "proto.keyword", "size": 10}
                    }
                }
            }
        )
        aggs = res.get("aggregations", {})
        stats["total_protocols"] = int(aggs.get("total_protos", {}).get("value", 0))
        buckets = aggs.get("protocols", {}).get("buckets", [])
        stats["protocol_breakdown"] = [{"protocol": b["key"], "count": b["doc_count"]} for b in buckets]
    except Exception: pass

    try:
        # Agg 5: Direction (Sum from Dashboard documents)
        from collections import Counter
        res_dir = es.search(
            index=PCAP_DASHBOARD_INDEX,
            body={
                "size": 1000,
                "_source": ["direction_breakdown"]
            }
        )
        dir_totals = Counter()
        for hit in res_dir["hits"]["hits"]:
            breakdown = hit["_source"].get("direction_breakdown", [])
            for item in breakdown:
                label = item.get("label")
                value = item.get("value", 0)
                if label:
                    dir_totals[label] += value
        
        stats["direction_breakdown"] = [{"label": k, "value": v} for k, v in dir_totals.items()]
    except Exception: pass

    return stats




def get_ip_breakdown(pcap_id=None):
    es = get_es()
    if not es: return {"isps": [], "countries": [], "cities": []}

    query = {"match_all": {}}
    if pcap_id: query = {"term": {"pcap_id": pcap_id}}

    def make_agg(field):
        return {
            "terms": {"field": field, "size": 1000},
            "aggs": {
                "packets": {"sum": {"field": "packet_count"}},
                "unique_ips": {"cardinality": {"field": "ip"}}
            }
        }

    aggs = {
        "isps": make_agg("isp"),
        "countries": make_agg("country"),
        "cities": make_agg("city")
    }

    try:
        res = es.search(index=PCAP_IPS_INDEX, body={"query": query, "aggs": aggs, "size": 0})
        aggregations = res.get("aggregations", {})
        
        def extract(name):
            buckets = aggregations.get(name, {}).get("buckets", [])
            return [{"name": b["key"], "count": int(b.get("unique_ips", {}).get("value", 0)), "packets": int(b.get("packets", {}).get("value", 0))} for b in buckets]

        return {"isps": extract("isps"), "countries": extract("countries"), "cities": extract("cities")}
    except Exception:
        return {"isps": [], "countries": [], "cities": []}

def get_report_details(report_type, value):
    """
    Returns a detailed list of unique IPs for a specific ISP, City, or Country.
    """
    es = get_es()
    if not es: return []
    
    field_map = {'isp': 'isp', 'city': 'city', 'country': 'country'}
    field = field_map.get(report_type.lower())
    if not field: return []
    print(f"DEBUG: Querying {field} = '{value}'")
    
    body = {
        "size": 0,
        "query": {"term": {field: value}},
        "aggs": {
            "unique_ips": {
                "terms": {"field": "ip", "size": 10000},
                "aggs": {
                    "packets": {"sum": {"field": "packet_count"}},
                    "isp": {"terms": {"field": "isp", "size": 1, "missing": "Unknown"}},
                    "city": {"terms": {"field": "city", "size": 1, "missing": "Unknown"}},
                    "country": {"terms": {"field": "country", "size": 1, "missing": "Unknown"}}
                }
            }
        }
    }
    
    try:
        res = es.search(index=PCAP_IPS_INDEX, body=body)
        buckets = res.get("aggregations", {}).get("unique_ips", {}).get("buckets", [])
        
        results = []
        for b in buckets:
            isp_buckets = b.get("isp", {}).get("buckets", [])
            city_buckets = b.get("city", {}).get("buckets", [])
            country_buckets = b.get("country", {}).get("buckets", [])
            
            isp = isp_buckets[0].get("key", "Unknown") if isp_buckets else "Unknown"
            city = city_buckets[0].get("key", "Unknown") if city_buckets else "Unknown"
            country = country_buckets[0].get("key", "Unknown") if country_buckets else "Unknown"
            
            results.append({
                "ip": b["key"],
                "packets": int(b.get("packets", {}).get("value", 0)),
                "isp": isp, "city": city, "country": country
            })
            
        results.sort(key=lambda x: x['packets'], reverse=True)
        return results
    except Exception as e:
        print(f"Details Error: {e}")
        return []

def get_dns_breakdown(pcap_id=None):
    es = get_es()
    if not es: return []

    query = {"match_all": {}}
    if pcap_id: query = {"term": {"pcap_id": pcap_id}}

    aggs = {
        "domains": {
            "terms": {"field": "domain", "size": 100},
            "aggs": {"count": {"sum": {"field": "count"}}}
        }
    }

    try:
        res = es.search(index=PCAP_DNS_INDEX, body={"query": query, "aggs": aggs, "size": 0})
        buckets = res.get("aggregations", {}).get("domains", {}).get("buckets", [])
        return [{b["key"]: int(b.get("count", {}).get("value", 0))} for b in buckets]
    except Exception:
        return []

# Scan Index helpers
def index_ip_scan(scan_data):
    es = get_es()
    if not es: return None
    ip = scan_data.get("ip")
    geo = scan_data.get("geo", {})
    if geo.get("lat") and geo.get("lon"):
        geo["location"] = {"lat": geo["lat"], "lon": geo["lon"]}
    scan_data["geo"] = geo
    try:
        return es.index(index=SCAN_INDEX, id=ip, body=scan_data)
    except Exception:
        return None

def get_ip_scan(ip):
    es = get_es()
    if not es: return None
    try:
        return es.get(index=SCAN_INDEX, id=ip)["_source"]
    except NotFoundError:
        try:
            return es.get(index=SCAN_INDEX_LEGACY, id=ip)["_source"]
        except NotFoundError:
            return None


# ---------------- LEGACY COMPAT ----------------

def get_payloads_summary(pcap_id):
    """Fetch summary of files and payloads for a specific pcap_id."""
    es = get_es()
    if not es: return []
    
    try:
        res = es.search(
            index=PCAP_PAYLOADS_INDEX,
            body={
                "query": {"term": {"pcap_id": pcap_id}},
                "size": 1000,
                "sort": [{"total_size": "desc"}]
            }
        )
        hits = res.get("hits", {}).get("hits", [])
        return [h["_source"] for h in hits]
    except Exception:
        return []

def get_pcap_analytics(pcap_id):
    """Fetch a single PCAP summary from the captures index."""
    return get_pcap_summary(pcap_id)


def get_all_pcap_analyses():
    """Return all PCAP summaries sorted by timestamp."""
    return get_all_pcap_summaries()


def get_geo_grid_aggregation(precision=3):
    """
    Groups 50,000+ IPs into geographical clusters using Geo-Grid aggregation.
    Returns lat/lon centroids and counts for each cluster.
    """
    es = get_es()
    if not es:
        return []

    body = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"term": {"is_internal": False}}
                ],
                "must_not": [
                    {"term": {"latitude": 0}},
                    {"term": {"longitude": 0}}
                ]
            }
        },
        "aggs": {
            "grid": {
                "geohash_grid": {
                    "field": "location",
                    "precision": precision
                },
                "aggs": {
                    "centroid": {
                        "geo_centroid": {"field": "location"}
                    },
                    "unique_ips": {
                        "cardinality": {"field": "ip"}
                    }
                }
            }
        }
    }

    try:
        res = es.search(index=PCAP_IPS_INDEX, body=body)
        buckets = res.get("aggregations", {}).get("grid", {}).get("buckets", [])
        
        points = []
        for b in buckets:
            centroid = b.get("centroid", {}).get("location", {})
            unique_count = b.get("unique_ips", {}).get("value", 0)
            if centroid:
                points.append({
                    "lat": centroid.get("lat"),
                    "lon": centroid.get("lon"),
                    "count": int(unique_count),
                    "hits": b["doc_count"], # Keep original doc count as 'hits' if needed
                    "geohash": b["key"]
                })
        return points

    except Exception as e:
        print(f"✗ Geo Grid Aggregation Error: {e}")
        return []


def get_recent_logs_from_es(log_type, timeline=None, page=1, per_page=50, pcap_id=None):
    es = get_es()
    if not es:
        return {"logs": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 0}

    index_name = f"zeek-{log_type}"
    query = {"bool": {"must": []}}
    if pcap_id:
        query["bool"]["must"].append({"term": {"pcap_id": pcap_id}})

    try:
        start = (page - 1) * per_page
        res = es.search(
            index=index_name,
            body={"query": query, "from": start, "size": per_page,
                  "sort": [{"@timestamp": {"order": "desc"}}]}
        )
        hits = res["hits"]["hits"]
        total = res["hits"]["total"]["value"]
        total_pages = math.ceil(total / per_page) if per_page > 0 else 0
        return {"logs": [h["_source"] for h in hits], "total": total,
                "page": page, "per_page": per_page, "total_pages": total_pages}
    except Exception as e:
        raise e


def get_geo_aggregation(pcap_id=None):
    """Aggregate ISP/Country/City from the granular pcap-ips index."""
    return get_ip_breakdown(pcap_id)
