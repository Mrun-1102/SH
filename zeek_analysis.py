from collections import Counter, defaultdict
import glob
import heapq
import ipaddress
import json
import os
import subprocess
from datetime import datetime, timezone
from urllib.parse import urlparse
from elasticsearch import helpers

import dpkt
try:
    import pyzeek
except Exception:
    pyzeek = None

from geo_ip import enrich_external_ips_with_geo
import elastic
from threat_intel import analyze_threat_intel


def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions


def get_elasticsearch_status(es, es_host):
    if es is None:
        return False, 'Elasticsearch client not initialized'

    try:
        health = es.cluster.health(request_timeout=3)
        cluster_status = str(health.get('status', 'unknown')).lower()

        if cluster_status in {'green', 'yellow'}:
            return True, f'Connected to {es_host} ({cluster_status})'
        if cluster_status == 'red':
            return False, f'Cluster is RED at {es_host}'

        return False, f'Cluster status unknown at {es_host} ({cluster_status})'
    except Exception as error:
        try:
            if es.ping(request_timeout=3):
                return True, f'Connected to {es_host}'
        except Exception:
            pass
        return False, f'Connection error: {error}'


def get_site_status_context(es, es_host):
    connected, message = get_elasticsearch_status(es, es_host)
    return {
        'elastic_connected': connected,
        'elastic_message': message,
        'elasticsearch_connected': connected,
        'elasticsearch_message': message,
        'elasticsearch_host': es_host,
    }


def process_pcap_with_zeek(pcap_path, output_dir, zeek_bin):
    try:
        os.makedirs(output_dir, exist_ok=True)
        cmd = [
            zeek_bin,
            '-C',
            '-r', pcap_path,
            '-e', 'redef LogAscii::use_json = T;',
            '-e', f'redef Log::default_logdir = "{output_dir}";',
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            return False, f"Zeek processing failed: {result.stderr}"
        return True, 'PCAP processed successfully'
    except subprocess.TimeoutExpired:
        return False, 'Zeek processing timeout'
    except FileNotFoundError:
        return False, 'Zeek not installed. Please install Zeek first.'
    except Exception as error:
        return False, f'Error processing PCAP: {error}'


def _record_to_dict(record):
    if isinstance(record, dict):
        return record

    if hasattr(record, 'to_dict'):
        try:
            data = record.to_dict()
            if isinstance(data, dict):
                return data
        except Exception:
            pass

    if hasattr(record, '_asdict'):
        try:
            data = record._asdict()
            if isinstance(data, dict):
                return data
        except Exception:
            pass

    if hasattr(record, '__dict__'):
        try:
            return {key: value for key, value in record.__dict__.items() if not key.startswith('_')}
        except Exception:
            pass

    try:
        data = dict(record)
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    return {}


def _normalize_pyzeek_result(records):
    normalized = []
    for record in records:
        data = _record_to_dict(record)
        if data:
            normalized.append(data)
    return normalized


def _parse_zeek_log_with_pyzeek(log_path):
    if pyzeek is None:
        return []

    attempts = []
    if hasattr(pyzeek, 'read'):
        attempts.append(lambda: pyzeek.read(log_path))
    if hasattr(pyzeek, 'parse'):
        attempts.append(lambda: pyzeek.parse(log_path))
    if hasattr(pyzeek, 'Reader'):
        attempts.append(lambda: list(pyzeek.Reader(log_path)))

    for attempt in attempts:
        try:
            result = attempt()
            if result is None:
                continue
            parsed = _normalize_pyzeek_result(result)
            if parsed:
                return parsed
        except Exception:
            continue

    return []


def parse_zeek_log(log_path):
    pyzeek_logs = _parse_zeek_log_with_pyzeek(log_path)
    if pyzeek_logs:
        return pyzeek_logs

    logs = []
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as handle:
            fields = []
            types = []

            for line in handle:
                line = line.strip()
                if not line:
                    continue

                if line.startswith('#fields'):
                    fields = line.split('\t')[1:]
                    continue

                if line.startswith('#types'):
                    types = line.split('\t')[1:]
                    continue

                if line.startswith('#'):
                    continue

                try:
                    if line.startswith('{'):
                        logs.append(json.loads(line))
                        continue

                    if fields:
                        values = line.split('\t')
                        if len(values) != len(fields):
                            continue

                        entry = {}
                        for index, field in enumerate(fields):
                            value = values[index]
                            field_type = types[index] if index < len(types) else None

                            if value == '-':
                                entry[field] = None
                            elif field_type in {'count', 'int'}:
                                try:
                                    entry[field] = int(value)
                                except ValueError:
                                    entry[field] = value
                            elif field_type in {'double', 'interval'}:
                                try:
                                    entry[field] = float(value)
                                except ValueError:
                                    entry[field] = value
                            else:
                                entry[field] = value

                        logs.append(entry)
                except Exception:
                    continue

        return logs
    except Exception:
        return []


def index_to_elasticsearch(es, es_host, log_type, logs, pcap_id):
    connected, message = get_elasticsearch_status(es, es_host)
    if not connected:
        return False, message

    try:
        index_name = f'zeek-{log_type}'
        actions = []
        for log in logs:
            # Use original traffic timestamp if available, fallback to analysis time
            ts = log.get('ts')
            if ts:
                try:
                    log['@timestamp'] = datetime.fromtimestamp(float(ts), timezone.utc).isoformat()
                except (ValueError, TypeError):
                    log['@timestamp'] = datetime.now(timezone.utc).isoformat()
            else:
                 log['@timestamp'] = datetime.now(timezone.utc).isoformat()

            log['pcap_id'] = pcap_id
            log['log_type'] = log_type
            actions.append({
                "_index": index_name,
                "_source": log
            })
            
        if actions:
            helpers.bulk(es, actions)
            
        return True, f'Indexed {len(logs)} {log_type} logs'
    except Exception as error:
        return False, f'Elasticsearch indexing error: {error}'


def _is_private_ip(value):
    try:
        return ipaddress.ip_address(str(value)).is_private
    except Exception:
        return False


def _is_multicast_or_broadcast_ip(value):
    try:
        ip_obj = ipaddress.ip_address(str(value))
        return ip_obj.is_multicast or str(ip_obj).endswith('.255')
    except Exception:
        return False


def _format_counter(counter, limit=6):
    if limit is None:
        items = counter.most_common()
    else:
        items = counter.most_common(limit)
    return [{'label': label, 'value': count} for label, count in items]


def _normalize_domain(value):
    if value is None:
        return None

    text = str(value).strip().lower()
    if not text or text in {'-', 'unknown', 'n/a'}:
        return None

    parsed = urlparse(text if '://' in text else f'//{text}')
    host = parsed.hostname or text.split('/', 1)[0].split(':', 1)[0]
    host = host.rstrip('.')
    return host or None


def _build_time_series(logs):
    buckets = Counter()
    for log in logs:
        timestamp = log.get('@timestamp') or log.get('ts')
        if not timestamp:
            continue
        try:
            if isinstance(timestamp, (int, float)):
                epoch_seconds = float(timestamp)
            else:
                raw = str(timestamp).strip()
                try:
                    epoch_seconds = float(raw)
                except ValueError:
                    parsed = datetime.fromisoformat(raw.replace('Z', '+00:00'))
                    epoch_seconds = parsed.timestamp()

            packet_weight = int(log.get('orig_pkts') or 0) + int(log.get('resp_pkts') or 0)
            if packet_weight <= 0:
                packet_weight = 1

            bucket_start = epoch_seconds - (epoch_seconds % 30)
            parsed = datetime.fromtimestamp(bucket_start)
            bucket = parsed.strftime('%d/%m %I:%M %p').lower()
            buckets[bucket] += packet_weight
        except Exception:
            continue

    return [{'label': label, 'value': count} for label, count in sorted(buckets.items())]


def _latest_capture_id(upload_folder):
    captures = []
    for path in glob.glob(os.path.join(upload_folder, '*')):
        if not os.path.isfile(path):
            continue

        base = os.path.basename(path)
        pcap_id, _, original_name = base.partition('_')
        if len(pcap_id) == 8 and original_name:
            captures.append((os.path.getmtime(path), pcap_id, original_name))

    if not captures:
        return None, None

    captures.sort(reverse=True)
    _, pcap_id, file_name = captures[0]
    return pcap_id, file_name


def _get_uploaded_file_name(upload_folder, pcap_id):
    latest_pcap_id, file_name = _latest_capture_id(upload_folder)
    if latest_pcap_id == pcap_id and file_name:
        return file_name

    for path in glob.glob(os.path.join(upload_folder, '*')):
        if not os.path.isfile(path):
            continue

        base = os.path.basename(path)
        current_pcap_id, _, original_name = base.partition('_')
        if current_pcap_id == pcap_id and original_name:
            return original_name

    return pcap_id


def _get_uploaded_file_path(upload_folder, pcap_id):
    for path in glob.glob(os.path.join(upload_folder, '*')):
        if not os.path.isfile(path):
            continue

        base = os.path.basename(path)
        current_pcap_id, _, _ = base.partition('_')
        if current_pcap_id == pcap_id:
            return path

    return None


def _get_exact_pcap_packet_count(upload_folder, pcap_id):
    pcap_path = _get_uploaded_file_path(upload_folder, pcap_id)
    if not pcap_path:
        return None

    try:
        with open(pcap_path, 'rb') as handle:
            try:
                reader = dpkt.pcap.Reader(handle)
            except (ValueError, dpkt.dpkt.NeedData):
                handle.seek(0)
                reader = dpkt.pcapng.Reader(handle)

            packet_count = 0
            for _ in reader:
                packet_count += 1

            return packet_count
    except Exception:
        return None


def _capture_logs_for(zeek_logs_folder, pcap_id):
    log_dir = os.path.join(zeek_logs_folder, pcap_id)
    logs = {
        'conn': [],
        'dns': [],
        'http': [],
        'ssl': [],
        'files': [],
        'ftp': [],
    }

    for log_type in logs:
        log_path = os.path.join(log_dir, f'{log_type}.log')
        if os.path.exists(log_path):
            logs[log_type] = parse_zeek_log(log_path)

    return logs


def _pick_value(data, *keys):
    for key in keys:
        value = data.get(key)
        if value not in (None, '', '-'):
            return value
    return None


def _build_external_ip_connections(conn_logs):
    external_to_internal = defaultdict(lambda: defaultdict(int))
    
    for log in conn_logs:
        origin = _pick_value(log, 'id.orig_h', 'orig_h', 'source')
        destination = _pick_value(log, 'id.resp_h', 'resp_h', 'destination')
        conn_packets = int(log.get('orig_pkts') or 0) + int(log.get('resp_pkts') or 0)
        if conn_packets <= 0:
            conn_packets = 1
        
        
        if origin and destination:
            if _is_private_ip(origin) and not _is_private_ip(destination):
                
                external_to_internal[str(destination)][str(origin)] += conn_packets
            elif not _is_private_ip(origin) and _is_private_ip(destination):
                
                external_to_internal[str(origin)][str(destination)] += conn_packets
    
    
    result = {}
    for external_ip, internal_dict in external_to_internal.items():
        result[external_ip] = {
            'internal_ips': [
                {'ip': internal_ip, 'packet_count': count}
                for internal_ip, count in sorted(internal_dict.items(), key=lambda x: x[1], reverse=True)
            ]
        }
    
    return result


def _build_internal_connections(conn_logs):
    internal_connections = defaultdict(lambda: defaultdict(int))

    for log in conn_logs:
        origin = _pick_value(log, 'id.orig_h', 'orig_h', 'source')
        destination = _pick_value(log, 'id.resp_h', 'resp_h', 'destination')
        conn_packets = int(log.get('orig_pkts') or 0) + int(log.get('resp_pkts') or 0)
        if conn_packets <= 0:
            conn_packets = 1

        if origin and destination and _is_private_ip(origin) and _is_private_ip(destination):
            internal_connections[str(origin)][str(destination)] += conn_packets

    rows = []
    for internal_ip, peers in internal_connections.items():
        for connected_ip, count in sorted(peers.items(), key=lambda x: x[1], reverse=True):
            rows.append({
                'internal_ip': internal_ip,
                'connected_ip': connected_ip,
                'packet_count': count,
                'connection_type': 'internal',
            })

    return rows


def _normalize_external_geo_rows(external_ips):
    normalized = []
    for item in external_ips or []:
        row = dict(item)
        try:
            lat = float(row.get('latitude')) if row.get('latitude') is not None else None
            lon = float(row.get('longitude')) if row.get('longitude') is not None else None
        except (TypeError, ValueError):
            lat = None
            lon = None

        if lat is not None and lon is not None and lat == 0.0 and lon == 0.0:
            lat = None
            lon = None

        row['latitude'] = lat
        row['longitude'] = lon
        normalized.append(row)

    return normalized


def _prepare_elastic_data(pcap_id, file_name, external_ips, external_ip_connections, internal_connections, dns_queries=None, ioc_domains=None, ioc_urls=None, extra_stats=None):
    enriched_external_ips = []
    
    for ext_ip_obj in external_ips:
        ip = ext_ip_obj.get('ip')
        connections = external_ip_connections.get(ip, {})
        
        enriched_ip = {
            'ip': ext_ip_obj.get('ip'),
            'packet_count': ext_ip_obj.get('packet_count'),
            'country': ext_ip_obj.get('country'),
            'city': ext_ip_obj.get('city'),
            'latitude': ext_ip_obj.get('latitude'),
            'longitude': ext_ip_obj.get('longitude'),
            'isp': ext_ip_obj.get('isp'),
            'internal_ips': connections.get('internal_ips', [])
        }
        enriched_external_ips.append(enriched_ip)
    
    extra_stats = extra_stats or {}
    return {
        'pcap_id': pcap_id,
        'pcap_filename': file_name,
        'total_packets': extra_stats.get('total_packets', 0),
        'duration_seconds': extra_stats.get('duration_seconds'),
        'total_bytes': extra_stats.get('total_bytes', 0),
        'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
        'external_ips': enriched_external_ips,
        'internal_connections': internal_connections,
        'dns_queries': dns_queries,
        'ioc_domains': ioc_domains,
        'ioc_urls': ioc_urls
    }



def build_dashboard_stats(upload_folder, zeek_logs_folder, pcap_id=None, force_rebuild=False):
    if pcap_id is None:
        pcap_id, file_name = _latest_capture_id(upload_folder)
    else:
        file_name = None

    if not pcap_id:
        return {
            'file_id': None,
            'file_name': None,
            'total_packets': 0,
            'total_connections': 0,
            'exact_pcap_packets': None,
            'total_bytes': 0,
            'duration_seconds': None,
            'start_time_utc': None,
            'end_time_utc': None,
            'transport_breakdown': [],
            'application_breakdown': [],
            'direction_breakdown': [],
            'dns_breakdown': [],
            'dns_domains': [],
            'url_domains': [],
            'ssl_servers': [],
            'destinations': [],
            'top_dns_domains': [],
            'top_url_domains': [],
            'top_ssl_servers': [],
            'top_destinations': [],
            'time_series': [],
            'recent_connections': [],
            'external_ips': [],
            'internal_ips': [],
            'dns_queries': [],
            'ioc_ips': [],
            'ioc_domains': [],
            'ioc_urls': [],
            'protocols': [],
            'ports': [],
            'user_agents': [],
            'file_payloads': [],
            'ftp_session': {},
            'summary': {},
        }

    stats_cache_path = os.path.join(zeek_logs_folder, pcap_id, 'dashboard_stats.json')
    if not force_rebuild and os.path.exists(stats_cache_path):
        try:
            with open(stats_cache_path, 'r') as f:
                cached_data = json.load(f)
                # Check if it was a full build
                if cached_data.get('file_id') == pcap_id:
                    return cached_data
        except: pass

    if not force_rebuild:
        dashboard_doc = elastic.get_dashboard_document(pcap_id)
        if dashboard_doc and dashboard_doc.get('file_id') == pcap_id:
            return dashboard_doc

    # Fallback to parsing from Zeek logs
    logs = _capture_logs_for(zeek_logs_folder, pcap_id)
    conn_logs = logs['conn']
    dns_logs = logs['dns']
    http_logs = logs['http']
    ssl_logs = logs['ssl']
    files_logs = logs['files']
    ftp_logs = logs['ftp']

    transport_counts = Counter()
    application_counts = Counter()
    direction_counts = Counter()
    dns_domain_counts = Counter()
    url_domain_counts = Counter()
    ssl_server_counts = Counter()
    destination_counts = Counter()
    external_ip_counts = Counter()
    internal_ip_counts = Counter()
    port_counts = Counter()
    user_agents = []
    seen_user_agents = set()
    total_ip_bytes = 0
    source_ips = set()
    observed_hosts = set()
    timestamps = []

    for log in conn_logs:
        proto = str(_pick_value(log, 'proto', 'transport', 'service') or 'unknown').upper()
        service = str(_pick_value(log, 'service', 'proto') or 'unknown')
        origin = _pick_value(log, 'id.orig_h', 'orig_h', 'source')
        destination = _pick_value(log, 'id.resp_h', 'resp_h', 'destination')
        port = _pick_value(log, 'id.resp_p', 'resp_p', 'port')
        conn_packets = int(log.get('orig_pkts') or 0) + int(log.get('resp_pkts') or 0)
        if conn_packets <= 0:
            conn_packets = 1

        if origin:
            source_ips.add(origin)
            observed_hosts.add(str(origin))
        if destination:
            observed_hosts.add(str(destination))
            destination_counts[str(destination)] += conn_packets
            if _is_private_ip(destination):
                internal_ip_counts[str(destination)] += conn_packets
            else:
                external_ip_counts[str(destination)] += conn_packets

        if origin and _is_private_ip(origin):
            internal_ip_counts[str(origin)] += conn_packets

        if port is not None:
            port_counts[(str(port), proto)] += conn_packets

        transport_counts[proto] += conn_packets
        application_counts[service] += conn_packets
        total_ip_bytes += int(log.get('orig_ip_bytes') or 0) + int(log.get('resp_ip_bytes') or 0)

        ts = log.get('ts')
        if ts is not None:
            try:
                timestamps.append(float(ts))
            except Exception:
                pass

        if _is_private_ip(origin) and not _is_private_ip(destination):
            direction_counts['Outbound'] += conn_packets
        elif not _is_private_ip(origin) and _is_private_ip(destination):
            direction_counts['Inbound'] += conn_packets
        elif _is_private_ip(origin) and _is_private_ip(destination):
            direction_counts['Internal'] += conn_packets
        else:
            direction_counts['External'] += conn_packets

    for log in dns_logs:
        query = _normalize_domain(log.get('query') or log.get('qname'))
        if query:
            dns_domain_counts[query] += 1

    for log in http_logs:
        host = _normalize_domain(_pick_value(log, 'host', 'referrer', 'uri'))
        if host:
            url_domain_counts[host] += 1

        user_agent = _pick_value(log, 'user_agent', 'ua', 'headers.user-agent')
        if user_agent and user_agent not in seen_user_agents:
            seen_user_agents.add(user_agent)
            user_agents.append({'user_agent': user_agent})

    for log in ssl_logs:
        server_name = _normalize_domain(log.get('server_name'))
        if not server_name:
            # Fallback to subject or issuer for certificate identity
            subject = log.get('subject')
            if subject and 'CN=' in str(subject):
                server_name = _normalize_domain(str(subject).split('CN=')[-1].split(',')[0])
                
        if server_name:
            ssl_server_counts[server_name] += 1

    dns_queries = []
    for log in dns_logs:
        domain = _normalize_domain(_pick_value(log, 'query', 'qname'))
        if not domain:
            continue
        dns_queries.append({
            'domain': domain,
            'record_type': _pick_value(log, 'qtype_name', 'qtype', 'rcode_name') or 'A',
            'timestamp': _pick_value(log, 'ts'),
        })

    recent_connections = sorted(
        conn_logs,
        key=lambda item: float(item.get('ts') or 0),
        reverse=True,
    )[:10]

    external_ips = [
        {'ip': ip, 'packet_count': count, 'country': None, 'isp': None}
        for ip, count in external_ip_counts.most_common()
    ]
    external_ips = enrich_external_ips_with_geo(external_ips)
    raw_external_ips = [row.copy() for row in external_ips] 
    external_ips = _normalize_external_geo_rows(external_ips)
    
    
    
    
    internal_ips = [
        {'ip': ip, 'packet_count': count, 'remarks': 'Internal host'}
        for ip, count in internal_ip_counts.most_common()
    ]
    ioc_ips = [
        {'ip': ip, 'reason': 'Repeated external connections' if count >= 3 else 'Observed on outbound traffic'}
        for ip, count in external_ip_counts.most_common()
    ]
    ioc_domains = []
    for domain, count in (dns_domain_counts + url_domain_counts).most_common():
        reason = 'Repeated DNS or HTTP usage' if count >= 2 else 'Observed in application traffic'
        ioc_domains.append({'domain': domain, 'reason': reason})

    ioc_urls = []
    for log in http_logs:
        host = _normalize_domain(_pick_value(log, 'host', 'referrer'))
        uri = _pick_value(log, 'uri', 'path') or '/'
        method = _pick_value(log, 'method', 'verb') or 'GET'
        url = f'https://{host}{uri}' if host and not str(uri).startswith('http') else str(uri)
        purpose = _pick_value(log, 'user_agent', 'server_name', 'mime_type') or 'HTTP activity'
        if url:
            ioc_urls.append({'url': url, 'method': method, 'purpose': purpose})

    protocol_rows = [{'protocol': protocol, 'packet_count': count} for protocol, count in transport_counts.most_common()]
    port_rows = [{'port': port, 'protocol': protocol, 'usage': count} for (port, protocol), count in port_counts.most_common()]
    alerts = analyze_threat_intel(conn_logs, dns_logs, http_logs)
    file_payloads = []
    for log in files_logs:
        protocol_value = _pick_value(log, 'analyzer', 'proto', 'service')
        source_value = _pick_value(log, 'source')
        protocol_text = str(protocol_value).strip() if protocol_value is not None else ''
        source_text = str(source_value).strip() if source_value is not None else ''

        
        if not protocol_text or protocol_text.lower() in {'unknown', '-', 'n/a'}:
            if source_text and source_text.lower() not in {'unknown', '-', 'n/a'}:
                protocol_text = source_text

        file_payloads.append({
            'filename': _pick_value(log, 'filename', 'fuid', 'name') or 'unknown',
            'type': _pick_value(log, 'mime_type', 'mimetype') or 'unknown',
            'protocol': protocol_text.upper() if protocol_text else 'unknown',
            'destination_ip': _pick_value(log, 'tx_hosts', 'rx_hosts', 'source'),
        })

    ftp_session = {}
    if ftp_logs:
        ftp_log = ftp_logs[0]
        ftp_session = {
            'source_ip': _pick_value(ftp_log, 'id.orig_h', 'orig_h', 'source_ip'),
            'destination_ip': _pick_value(ftp_log, 'id.resp_h', 'resp_h', 'destination_ip'),
            'port': _pick_value(ftp_log, 'id.resp_p', 'resp_p', 'port'),
            'server_banner': _pick_value(ftp_log, 'reply_msg', 'server_banner', 'banner'),
            'username': _pick_value(ftp_log, 'user', 'username'),
            'password': _pick_value(ftp_log, 'password', 'pass'),
            'command': _pick_value(ftp_log, 'command', 'cmd'),
            'file_transferred': _pick_value(ftp_log, 'filename', 'file_name', 'fuid'),
            'data_channel': _pick_value(ftp_log, 'data_channel', 'data_conn'),
            'data_type': _pick_value(ftp_log, 'data_type', 'mime_type'),
        }

    start_time = None
    end_time = None
    duration_seconds = None
    if timestamps:
        start_time = datetime.utcfromtimestamp(min(timestamps)).replace(tzinfo=timezone.utc).isoformat()
        end_time = datetime.utcfromtimestamp(max(timestamps)).replace(tzinfo=timezone.utc).isoformat()
        if len(timestamps) > 1:
            duration_seconds = round(max(timestamps) - min(timestamps), 3)

    file_name = file_name or _get_uploaded_file_name(upload_folder, pcap_id)
    exact_pcap_packets = _get_exact_pcap_packet_count(upload_folder, pcap_id)

    
    aligned_dns_queries = sum(1 for log in dns_logs if str(log.get('opcode_name') or '').lower() != 'netbios-query')
    aligned_http_requests = len(http_logs)
    aligned_total_bytes = total_ip_bytes
    aligned_unique_sources = len({host for host in observed_hosts if not _is_multicast_or_broadcast_ip(host)})

    stats_return_obj = {
        'file_id': pcap_id,
        'file_name': file_name,
        'total_packets': exact_pcap_packets if exact_pcap_packets is not None else 0,
        'total_connections': len(conn_logs),
        'exact_pcap_packets': exact_pcap_packets,
        'total_dns_queries': aligned_dns_queries,
        'total_http_requests': aligned_http_requests,
        'total_bytes': aligned_total_bytes,
        'duration_seconds': duration_seconds,
        'attack_duration_seconds': duration_seconds,
        'start_time_utc': start_time,
        'end_time_utc': end_time,
        'malware_type': 'Suspicious network activity',
        'infected_host': str(max(internal_ip_counts, key=internal_ip_counts.get)) if internal_ip_counts else 'Unknown',
        'reputation_status': 'CLEAN',
        'unique_sources': aligned_unique_sources,
        'transport_breakdown': _format_counter(transport_counts),
        'application_breakdown': _format_counter(application_counts),
        'direction_breakdown': _format_counter(direction_counts),
        'dns_breakdown': _format_counter(dns_domain_counts),
        'dns_domains': _format_counter(dns_domain_counts, limit=None),
        'url_domains': _format_counter(url_domain_counts, limit=None),
        'ssl_servers': _format_counter(ssl_server_counts, limit=None),
        'destinations': _format_counter(destination_counts, limit=12),
        'top_dns_domains': _format_counter(dns_domain_counts, limit=10),
        'top_url_domains': _format_counter(url_domain_counts, limit=10),
        'top_ssl_servers': _format_counter(ssl_server_counts, limit=10),
        'top_destinations': _format_counter(destination_counts, limit=10),
        'time_series': _build_time_series(conn_logs),
        'recent_connections': recent_connections,
        'external_ips': external_ips,
        'internal_ips': internal_ips,
        'dns_queries': dns_queries,
        'ioc_ips': ioc_ips,
        'ioc_domains': ioc_domains,
        'ioc_urls': ioc_urls,
        'protocols': protocol_rows,
        'ports': port_rows,
        'user_agents': user_agents,
        'file_payloads': file_payloads,
        'ftp_session': ftp_session,
        'alerts': alerts,
        'raw_external_ips': raw_external_ips,
        'summary': {
            'unique_sources': aligned_unique_sources,
            'log_types': list(logs.keys()),
            'file_size': os.path.getsize(_get_uploaded_file_path(upload_folder, pcap_id)) if _get_uploaded_file_path(upload_folder, pcap_id) else 0
        },
    }

    # Save to cache
    try:
        os.makedirs(os.path.dirname(stats_cache_path), exist_ok=True)
        with open(stats_cache_path, 'w') as f:
            json.dump(stats_return_obj, f)
    except: pass

    # Pre-map HTTP URIs to extract proper filenames
    uid_to_filename = {}
    for h_log in http_logs:
        h_uid = h_log.get('uid')
        h_uri = h_log.get('uri')
        if h_uid and h_uri and h_uri != '-':
            clean_uri = str(h_uri).split('?')[0]
            if '/' in clean_uri:
                extracted = clean_uri.split('/')[-1]
                # Check for realistic extension (e.g., .exe, .pdf, .cab)
                if extracted and len(extracted) > 1 and '.' in extracted[-6:]:
                    uid_to_filename[h_uid] = extracted

    # Files and Payloads aggregation
    payloads_data = []
    files_map = {}
    for fl in files_logs:
        # Create a unique key based on source, mime, and filename
        source = fl.get('source', 'Unknown')
        mime = fl.get('mime_type')
        if not mime or mime == '(empty)' or mime == '-': mime = 'Unknown'
        
        fname = fl.get('filename')
        uid = fl.get('uid') or fl.get('conn_uids', '').split(',')[0]
        
        if not fname or fname == '-':
            # 1. Attempt to resolve proper filename from HTTP logs
            if uid and uid in uid_to_filename:
                fname = uid_to_filename[uid]
            # 2. Assign professional defaults for known application streams
            elif source == 'SSL':
                fname = "SSL/TLS Certificate Payload"
            elif source == 'HTTP':
                fname = "HTTP Binary Download"
            else:
                mime_part = mime.split('/')[-1] if mime and '/' in mime else 'data'
                fname = f"Network Stream ({mime_part})"
        
        size = int(fl.get('total_bytes') or fl.get('seen_bytes') or 0)
        key = f"{source}|{mime}|{fname}"
        
        if key not in files_map:
            files_map[key] = {
                'filename': fname,
                'mime_type': mime,
                'protocol': source,
                'total_size': 0,
                'count': 0
            }
        
        files_map[key]['total_size'] += size
        files_map[key]['count'] += 1

    payloads_data = list(files_map.values())
    print(f"DEBUG: payloads_data length: {len(payloads_data)}")

    # Index analysis for the dropdown context
    external_ip_connections = _build_external_ip_connections(conn_logs)
    internal_connections_flat = _build_internal_connections(conn_logs)
    
    extra_stats = {
        'total_packets': exact_pcap_packets if exact_pcap_packets is not None else 0,
        'duration_seconds': duration_seconds,
        'total_bytes': aligned_total_bytes
    }
    
    elastic_data = _prepare_elastic_data(
        pcap_id, file_name, external_ips, external_ip_connections, internal_connections_flat, 
        dns_queries=dns_queries, ioc_domains=ioc_domains, ioc_urls=ioc_urls,
        extra_stats=extra_stats
    )
    
    # Prepare Granular Data for the new strategy
    summary_data = {
        'total_packets': extra_stats.get('total_packets', 0),
        'duration_seconds': extra_stats.get('duration_seconds', 0),
        'total_bytes': extra_stats.get('total_bytes', 0),
        'file_size': os.path.getsize(os.path.join(upload_folder, pcap_id)) if os.path.exists(os.path.join(upload_folder, pcap_id)) else 0,
        'unique_ips': len(external_ips),
        'unique_domains': len(dns_domain_counts) + len(url_domain_counts),
        'traffic_start': start_time,
        'traffic_end': end_time
    }

    ips_data = []
    # External IPs
    for ip_obj in external_ips:
        ips_data.append({
            'ip': ip_obj.get('ip'),
            'packet_count': ip_obj.get('packet_count', 0),
            'country': ip_obj.get('country'),
            'city': ip_obj.get('city'),
            'isp': ip_obj.get('isp'),
            'latitude': ip_obj.get('latitude'),
            'longitude': ip_obj.get('longitude'),
            'is_internal': False
        })
    
    # Internal IPs
    for ip_obj in internal_ips:
        ips_data.append({
            'ip': ip_obj.get('ip'),
            'packet_count': ip_obj.get('packet_count', 0),
            'remarks': ip_obj.get('remarks'),
            'is_internal': True
        })

    
    dns_data = []
    for domain, count in dns_domain_counts.items():
        dns_data.append({'domain': domain, 'type': 'dns', 'count': count})
    for domain, count in url_domain_counts.items():
        dns_data.append({'domain': domain, 'type': 'http', 'count': count})

    try:
        elastic.bulk_index_granular_data(pcap_id, file_name, summary_data, ips_data, dns_data, payloads_data)
    except Exception as e:
        print(f"Warning: Failed to perform granular indexing: {e}")

    try:
        elastic.index_dashboard_document(pcap_id, stats_return_obj)
    except Exception as e:
        print(f"Warning: Failed to index dashboard document for {pcap_id}: {e}")

    return stats_return_obj


def index_capture_documents(upload_folder, zeek_logs_folder, pcap_id):
    """
    Orchestrates the entire indexing flow for a specific capture.
    Re-indexes both the summary and all granular log entries.
    """
    try:
        # 1. Update the metadata summaries and aggregate analytics
        build_dashboard_stats(upload_folder, zeek_logs_folder, pcap_id, force_rebuild=True)
        
        # 2. Re-index all granular logs (conn, dns, http, etc.) to apply new timestamp logic
        output_dir = os.path.join(zeek_logs_folder, pcap_id)
        if not os.path.isdir(output_dir):
            return False, f"Log directory not found: {output_dir}"

        from elastic import get_es, ES_HOST
        es = get_es()
        if not es:
            return False, "Elasticsearch not connected"

        indexed_count = 0
        for log_file in os.listdir(output_dir):
            if not log_file.endswith('.log'):
                continue
            
            log_type = log_file.replace('.log', '')
            log_path = os.path.join(output_dir, log_file)
            
            logs = parse_zeek_log(log_path)
            if logs:
                success, msg = index_to_elasticsearch(es, ES_HOST, log_type, logs, pcap_id)
                if success:
                    indexed_count += 1
        
        return True, f"Re-indexed metadata and {indexed_count} log types successfully"
    except Exception as e:
        print(f"Error in index_capture_documents: {e}")
        return False, str(e)


RECENT_CONN_LIMIT = 150
RECENT_CONN_PER_PAGE_MAX = 20

def build_recent_logs(zeek_logs_folder, log_type, page=None, per_page=None):
    logs = []
    for log_path in glob.glob(os.path.join(zeek_logs_folder, '*', f'{log_type}.log')):
        logs.extend(parse_zeek_log(log_path))

    if log_type == 'conn':
        logs = heapq.nlargest(RECENT_CONN_LIMIT, logs, key=lambda item: float(item.get('ts') or 0))

    if page is None and per_page is None:
        if log_type == 'conn':
            return logs
        return logs[:100]

    safe_page = max(page or 1, 1)
    max_per_page = RECENT_CONN_PER_PAGE_MAX if log_type == 'conn' else 500
    safe_per_page = min(max(per_page or 100, 1), max_per_page)
    total = len(logs)
    total_pages = max((total + safe_per_page - 1) // safe_per_page, 1)

    if safe_page > total_pages:
        safe_page = total_pages

    start = (safe_page - 1) * safe_per_page
    end = start + safe_per_page
    return {
        'logs': logs[start:end],
        'page': safe_page,
        'per_page': safe_per_page,
        'total': total,
        'total_pages': total_pages,
    }
