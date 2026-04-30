from flask import Flask, render_template, request, jsonify
import hashlib
import json
import os
import shutil
import threading
import urllib3
from collections import defaultdict
from datetime import datetime, timezone, timedelta

from werkzeug.utils import secure_filename

from zeek_analysis import (
    allowed_file,
    build_dashboard_stats,
    build_recent_logs,
    get_site_status_context,
    index_to_elasticsearch,
    process_pcap_with_zeek,
    parse_zeek_log,
)

from elastic import get_es  # ✅ shared ES instance
import elastic
import scanner

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__, template_folder='templates')
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'zeek_uploads')
app.config['ZEEK_LOGS_FOLDER'] = os.path.join(basedir, 'zeek_logs')
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024
app.config['ALLOWED_EXTENSIONS'] = {'pcap', 'pcapng'}

ZEEK_BIN = os.getenv('ZEEK_BIN', shutil.which('zeek') or 'zeek')

# Ensure index exists
es = get_es()
ES_HOST = os.getenv('ES_HOST', 'http://localhost:9200')

try:
    elastic.create_pcap_index()
    scanner.create_scan_index()
except Exception as e:
    print(f'Warning: Could not create Elasticsearch index: {e}')


# ---------------- ROUTES ----------------

@app.route('/')
def index():
    return render_template(
        'index.html',
        active_page='home',
        selected_pcap_id=request.args.get('pcap_id', ''),
        **get_site_status_context(es, ES_HOST)
    )


@app.route('/dashboard')
def dashboard():
    return render_template(
        'dashboard.html',
        active_page='dashboard',
        selected_pcap_id=request.args.get('pcap_id', ''),
        **get_site_status_context(es, ES_HOST)
    )


@app.route('/report')
def report():
    return render_template(
        'report.html',
        active_page='report',
        selected_pcap_id=request.args.get('pcap_id', ''),
        **get_site_status_context(es, ES_HOST)
    )


@app.route('/details')
def details():
    return render_template(
        'details.html',
        active_page='details',
        selected_pcap_id=request.args.get('pcap_id', ''),
        **get_site_status_context(es, ES_HOST)
    )


def _get_uploaded_file_path(upload_folder, pcap_id):
    """Finds the full path of a file in the upload folder starting with the pcap_id."""
    if not os.path.exists(upload_folder):
        return None
    for file in os.listdir(upload_folder):
        if file.startswith(f"{pcap_id}_"):
            return os.path.join(upload_folder, file)
    return None


def _get_zeek_log_path(zeek_logs_folder, pcap_id, log_type):
    log_path = os.path.join(zeek_logs_folder, pcap_id, f"{log_type}.log")
    if os.path.exists(log_path):
        return log_path
    return None


def _pick_first(record, *keys):
    for key in keys:
        value = record.get(key)
        if value not in (None, '', '-'):
            return value
    return None


def _timeline_to_cutoff(timeline):
    now = datetime.now(timezone.utc)
    if timeline == '1d':
        return now - timedelta(days=1)
    if timeline == '7d':
        return now - timedelta(days=7)
    if timeline == '15d':
        return now - timedelta(days=15)
    if timeline == '45d':
        return now - timedelta(days=45)
    if timeline == '90d':
        return now - timedelta(days=90)
    if timeline in {'6M', '6m'}:
        return now - timedelta(days=180)
    return None


def _load_local_connections(zeek_logs_folder, pcap_id, limit=100):
    log_path = _get_zeek_log_path(zeek_logs_folder, pcap_id, 'conn')
    if not log_path:
        return []

    conn_logs = parse_zeek_log(log_path)
    recent_connections = sorted(
        conn_logs,
        key=lambda item: float(item.get('ts') or 0),
        reverse=True,
    )
    return recent_connections[:limit]


def _load_local_connections_page(zeek_logs_folder, pcap_id, page=1, per_page=40, timeline=None):
    log_path = _get_zeek_log_path(zeek_logs_folder, pcap_id, 'conn')
    if not log_path:
        return {'logs': [], 'page': page, 'per_page': per_page, 'total': 0, 'total_pages': 0}

    conn_logs = parse_zeek_log(log_path)
    cutoff = _timeline_to_cutoff(timeline)
    if cutoff is not None:
        filtered_logs = []
        for log in conn_logs:
            ts_value = log.get('@timestamp') or log.get('ts')
            if ts_value is None:
                continue
            try:
                if isinstance(ts_value, (int, float)):
                    ts = datetime.fromtimestamp(float(ts_value), timezone.utc)
                else:
                    raw = str(ts_value).strip()
                    try:
                        ts = datetime.fromtimestamp(float(raw), timezone.utc)
                    except ValueError:
                        ts = datetime.fromisoformat(raw.replace('Z', '+00:00'))
                if ts >= cutoff:
                    filtered_logs.append(log)
            except Exception:
                continue
        conn_logs = filtered_logs

    recent_connections = sorted(
        conn_logs,
        key=lambda item: float(item.get('ts') or 0),
        reverse=True,
    )

    total = len(recent_connections)
    safe_per_page = max(1, min(per_page, 40))
    total_pages = max((total + safe_per_page - 1) // safe_per_page, 1) if total else 0
    safe_page = max(1, min(page, total_pages or 1))
    start_idx = (safe_page - 1) * safe_per_page
    end_idx = start_idx + safe_per_page

    return {
        'logs': recent_connections[start_idx:end_idx],
        'page': safe_page,
        'per_page': safe_per_page,
        'total': total,
        'total_pages': total_pages,
    }


def _normalize_recent_connection_row(log):
    ts_value = log.get('@timestamp') or log.get('ts')
    source_ip = log.get('id.orig_h') or log.get('orig_h') or log.get('source')
    dest_ip = log.get('id.resp_h') or log.get('resp_h') or log.get('destination')
    dest_port = log.get('id.resp_p') or log.get('resp_p') or log.get('port')
    protocol = log.get('proto') or log.get('transport') or log.get('protocol') or 'unknown'
    service = log.get('service') or log.get('proto') or 'unknown'
    duration = log.get('duration') or log.get('dur') or log.get('connection_duration')
    if duration in (None, '', '-'):
        duration = 0
    packet_bytes = log.get('orig_bytes')
    resp_bytes = log.get('resp_bytes')
    if packet_bytes in (None, '', '-') and resp_bytes in (None, '', '-'):
        packet_bytes = int(log.get('orig_ip_bytes') or 0) + int(log.get('resp_ip_bytes') or 0)
    else:
        packet_bytes = int(packet_bytes or 0) + int(resp_bytes or 0)

    status = log.get('conn_state') or log.get('state') or log.get('status') or 'unknown'

    return {
        'timestamp': ts_value,
        'source_ip': source_ip,
        'dest_ip': dest_ip,
        'dest_port': dest_port,
        'protocol': protocol,
        'service': service,
        'duration': duration,
        'bytes': packet_bytes,
        'status': status,
    }


def _load_local_file_payloads(zeek_logs_folder, pcap_id):
    log_path = _get_zeek_log_path(zeek_logs_folder, pcap_id, 'files')
    if not log_path:
        return []

    files_logs = parse_zeek_log(log_path)
    payloads = []
    for log in files_logs:
        protocol_value = _pick_first(log, 'analyzer', 'proto', 'service')
        source_value = _pick_first(log, 'source')
        protocol_text = str(protocol_value).strip() if protocol_value is not None else ''
        source_text = str(source_value).strip() if source_value is not None else ''

        if not protocol_text or protocol_text.lower() in {'unknown', '-', 'n/a'}:
            if source_text and source_text.lower() not in {'unknown', '-', 'n/a'}:
                protocol_text = source_text

        payloads.append({
            'filename': _pick_first(log, 'filename', 'fuid', 'name') or 'unknown',
            'type': _pick_first(log, 'mime_type', 'mimetype') or 'unknown',
            'protocol': protocol_text.upper() if protocol_text else 'unknown',
            'destination_ip': _pick_first(log, 'tx_hosts', 'rx_hosts', 'source'),
        })

    return payloads


def _discover_existing_pcap_ids(upload_folder):
    pcap_ids = []
    seen_ids = set()
    if not os.path.exists(upload_folder):
        return pcap_ids

    for file in os.listdir(upload_folder):
        filepath = os.path.join(upload_folder, file)
        if not os.path.isfile(filepath):
            continue

        if not (file.endswith('.pcap') or file.endswith('.pcapng')):
            continue

        parts = file.split('_', 1)
        if len(parts) != 2:
            continue

        pcap_id = parts[0]
        if not pcap_id or pcap_id in seen_ids:
            continue

        seen_ids.add(pcap_id)
        pcap_ids.append(pcap_id)

    return pcap_ids


def _backfill_existing_ip_intelligence():
    upload_folder = app.config['UPLOAD_FOLDER']
    zeek_logs_folder = app.config['ZEEK_LOGS_FOLDER']
    pcap_ids = _discover_existing_pcap_ids(upload_folder)

    print(f"[*] Starting IP intelligence backfill for {len(pcap_ids)} existing capture(s)...")
    total_queued = 0
    total_skipped = 0

    for pcap_id in pcap_ids:
        try:
            stats = build_dashboard_stats(
                upload_folder,
                zeek_logs_folder,
                pcap_id=pcap_id,
                force_rebuild=False
            )
            queued = scanner.enqueue_ip_intelligence_scans(
                stats.get('external_ips') or stats.get('raw_external_ips') or [],
                pcap_id=pcap_id,
                source='backfill'
            )
            total_queued += len(queued)
            total_skipped += max((len(stats.get('external_ips') or []) - len(queued)), 0)
            print(f"[*] Backfill for {pcap_id}: queued {len(queued)} IP scan(s)")
        except Exception as e:
            print(f"Warning: backfill failed for {pcap_id}: {e}")

    print(f"[*] IP intelligence backfill queued {total_queued} scan(s) across {len(pcap_ids)} capture(s)")
    return {
        'captures': len(pcap_ids),
        'queued': total_queued,
        'skipped': total_skipped,
    }


def _start_backfill_thread():
    def runner():
        try:
            _backfill_existing_ip_intelligence()
        except Exception as e:
            print(f"Warning: IP intelligence backfill crashed: {e}")

    thread = threading.Thread(target=runner, name='ip-intel-backfill', daemon=True)
    thread.start()
    return thread


# ---------------- HEALTH CHECK ----------------
@app.route('/api/health')
def health():
    try:
        if es and es.ping():
            return jsonify({"status": "ok"})
        return jsonify({"status": "es_down"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ---------------- FILE UPLOAD ----------------
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'pcapFile' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['pcapFile']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if file and allowed_file(file.filename, app.config['ALLOWED_EXTENSIONS']):
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        os.makedirs(app.config['ZEEK_LOGS_FOLDER'], exist_ok=True)

        filename = secure_filename(file.filename)
        timestamp = hashlib.md5(f"{filename}_{os.getpid()}_{os.urandom(8).hex()}".encode()).hexdigest()[:8]
        pcap_id = timestamp

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f'{pcap_id}_{filename}')
        file.save(filepath)

        output_dir = os.path.join(app.config['ZEEK_LOGS_FOLDER'], pcap_id)
        success, message = process_pcap_with_zeek(filepath, output_dir, ZEEK_BIN)

        if not success:
            return jsonify({'error': message}), 500

        indexed_logs = {}
        indexing_errors = {}

        for log_file in os.listdir(output_dir):
            if not log_file.endswith('.log'):
                continue

            log_type = log_file.replace('.log', '')
            logs = parse_zeek_log(os.path.join(output_dir, log_file))

            if logs:
                success, msg = index_to_elasticsearch(es, None, log_type, logs, pcap_id)

                if success:
                    indexed_logs[log_type] = len(logs)
                else:
                    indexing_errors[log_type] = msg

        try:
            stats = build_dashboard_stats(
                app.config['UPLOAD_FOLDER'],
                app.config['ZEEK_LOGS_FOLDER'],
                pcap_id=pcap_id,
                force_rebuild=True
            )
            scanner.enqueue_ip_intelligence_scans(
                stats.get('external_ips') or stats.get('raw_external_ips') or [],
                pcap_id=pcap_id,
                source='zeek_upload'
            )
        except Exception as e:
            print(f"Error building dashboard index for {pcap_id}: {e}")

        return api_response(data={
            'pcap_id': pcap_id,
            'message': 'PCAP processed successfully',
            'indexed_logs': indexed_logs,
            'indexing_errors': indexing_errors,
        })

    return jsonify({'error': 'Invalid file type'}), 400


# ---------------- API RESPONSE HELPER ----------------
def api_response(data, success=True, page=None, per_page=None, total=None, total_pages=None, error=None, meta=None):
    response = {
        'success': success,
        'data': data
    }
    if error:
        response['error'] = error

    if page is not None or per_page is not None or total is not None:
        response['pagination'] = {
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': total_pages
        }

    if meta:
        response.update(meta)

    return jsonify(response)


def _load_pcap_stats(pcap_id, force_rebuild=False):
    return build_dashboard_stats(
        app.config['UPLOAD_FOLDER'],
        app.config['ZEEK_LOGS_FOLDER'],
        pcap_id=pcap_id,
        force_rebuild=force_rebuild
    )


def _stats_counter_rows(stats, key, label_name, value_name, exclude_labels=None):
    excluded = {str(item).strip().lower() for item in (exclude_labels or [])}
    rows = []
    for item in stats.get(key, []) or []:
        label = item.get('label')
        if label is not None and str(label).strip().lower() in excluded:
            continue
        rows.append({
            label_name: label,
            value_name: item.get('value', 0)
        })
    return rows


def _build_domains_identified(stats):
    rows = []
    for item in stats.get('top_dns_domains', []) or []:
        rows.append({
            'domain': item.get('label'),
            'reason': 'dns',
            'count': item.get('value', 0)
        })
    for item in stats.get('top_url_domains', []) or []:
        rows.append({
            'domain': item.get('label'),
            'reason': 'http',
            'count': item.get('value', 0)
        })
    for item in stats.get('top_ssl_servers', []) or []:
        rows.append({
            'domain': item.get('label'),
            'reason': 'ssl',
            'count': item.get('value', 0)
        })
    return rows


def _build_nested_ip_groups(pcap_id, outer_field, inner_field, outer_key, inner_key):
    breakdown = elastic.get_ip_breakdown(pcap_id)
    outer_rows = breakdown.get(f'{outer_field}s', []) or []
    results = []

    for outer in outer_rows:
        outer_name = outer.get('name')
        if not outer_name:
            continue

        ip_rows = elastic.get_report_details(outer_field, outer_name)
        grouped = defaultdict(list)
        for row in ip_rows:
            group_name = row.get(inner_field) or 'Unknown'
            grouped[group_name].append(row.get('ip'))

        inner_items = []
        for name, ips in sorted(grouped.items(), key=lambda item: len(item[1]), reverse=True):
            inner_items.append({
                inner_key: name,
                'count': len(ips),
                'ips': ips,
            })

        inner_collection_key = 'cities' if inner_key == 'city' else f'{inner_key}s'

        results.append({
            outer_key: outer_name,
            'count': outer.get('count', 0),
            'packets': outer.get('packets', 0),
            inner_collection_key: inner_items,
        })

    return results


def _build_flat_ip_group_list(pcap_id, field_name, collection_key, output_key):
    breakdown = elastic.get_ip_breakdown(pcap_id)
    rows = breakdown.get(collection_key, []) or []
    results = []

    for row in rows:
        group_name = row.get('name')
        if not group_name:
            continue

        ip_rows = elastic.get_report_details(field_name, group_name)
        results.append({
            output_key: group_name,
            'count': row.get('count', 0),
            'packets': row.get('packets', 0),
            'ips': [item.get('ip') for item in ip_rows if item.get('ip')],
        })

    return results


def _build_pcaps_page(page=1, per_page=12, search=''):
    search = (search or '').lower()
    all_pcaps = []
    seen_ids = set()

    upload_folder = app.config['UPLOAD_FOLDER']
    if os.path.exists(upload_folder):
        for file in os.listdir(upload_folder):
            filepath = os.path.join(upload_folder, file)
            if os.path.isfile(filepath) and (file.endswith('.pcap') or file.endswith('.pcapng')):
                parts = file.split('_', 1)
                if len(parts) != 2:
                    continue

                pcap_id, filename = parts[0], parts[1]
                if pcap_id in seen_ids:
                    continue
                seen_ids.add(pcap_id)

                if search and search not in filename.lower():
                    continue

                file_size = os.path.getsize(filepath)
                all_pcaps.append({
                    'pcap_id': pcap_id,
                    'filename': filename,
                    'size': file_size,
                    'packets': None,
                    'duration': None,
                    'source': 'disk'
                })

    if es:
        try:
            res = es.search(
                index="pcap-captures",
                body={
                    "query": {"match_all": {}},
                    "size": 1000
                }
            )
            es_data = {}
            for hit in res['hits']['hits']:
                source = hit['_source']
                pcap_id = source.get('pcap_id')
                if pcap_id:
                    es_data[pcap_id] = {
                        'packets': source.get('total_packets'),
                        'duration': source.get('duration_seconds'),
                        'ip_count': source.get('unique_ips', 0)
                    }

            for item in all_pcaps:
                if item['pcap_id'] in es_data:
                    item['packets'] = item['packets'] or es_data[item['pcap_id']].get('packets')
                    item['duration'] = item['duration'] or es_data[item['pcap_id']].get('duration')
                    item['ip_count'] = es_data[item['pcap_id']].get('ip_count', 0)
        except Exception as es_err:
            print(f"ES enrichment failed: {es_err}")

    all_pcaps.sort(key=lambda x: x.get('filename', ''), reverse=False)
    total = len(all_pcaps)
    total_pages = (total + per_page - 1) // per_page if per_page > 0 else 1
    page = max(1, min(page, total_pages))

    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    page_data = all_pcaps[start_idx:end_idx]

    for item in page_data:
        if not item.get('packets') or not item.get('duration'):
            meta_path = os.path.join(app.config['ZEEK_LOGS_FOLDER'], item['pcap_id'], 'metadata.json')
            if os.path.exists(meta_path):
                try:
                    with open(meta_path, 'r') as f:
                        meta = json.load(f)
                        item['packets'] = item['packets'] or meta.get('packets')
                        item['duration'] = item['duration'] or meta.get('duration')
                except Exception:
                    pass

            if item.get('packets') is None:
                conn_log = os.path.join(app.config['ZEEK_LOGS_FOLDER'], item['pcap_id'], 'conn.log')
                if os.path.exists(conn_log):
                    try:
                        with open(conn_log, 'r') as f:
                            count = sum(1 for line in f if not line.startswith('#'))
                            item['packets'] = count
                    except Exception:
                        pass

    return page_data, page, per_page, total, total_pages


def _collect_all_pcaps(search=''):
    search = (search or '').lower()
    all_pcaps = []
    seen_ids = set()

    upload_folder = app.config['UPLOAD_FOLDER']
    if os.path.exists(upload_folder):
        for file in os.listdir(upload_folder):
            filepath = os.path.join(upload_folder, file)
            if os.path.isfile(filepath) and (file.endswith('.pcap') or file.endswith('.pcapng')):
                parts = file.split('_', 1)
                if len(parts) != 2:
                    continue

                pcap_id, filename = parts[0], parts[1]
                if pcap_id in seen_ids:
                    continue
                seen_ids.add(pcap_id)

                if search and search not in filename.lower():
                    continue

                file_size = os.path.getsize(filepath)
                all_pcaps.append({
                    'pcap_id': pcap_id,
                    'filename': filename,
                    'size': file_size,
                    'packets': None,
                    'duration': None,
                    'source': 'disk'
                })

    if es:
        try:
            res = es.search(
                index="pcap-captures",
                body={
                    "query": {"match_all": {}},
                    "size": 1000
                }
            )
            es_data = {}
            for hit in res['hits']['hits']:
                source = hit['_source']
                pcap_id = source.get('pcap_id')
                if pcap_id:
                    es_data[pcap_id] = {
                        'packets': source.get('total_packets'),
                        'duration': source.get('duration_seconds'),
                        'ip_count': source.get('unique_ips', 0)
                    }

            for item in all_pcaps:
                if item['pcap_id'] in es_data:
                    item['packets'] = item['packets'] or es_data[item['pcap_id']].get('packets')
                    item['duration'] = item['duration'] or es_data[item['pcap_id']].get('duration')
                    item['ip_count'] = es_data[item['pcap_id']].get('ip_count', 0)
        except Exception as es_err:
            print(f"ES enrichment failed: {es_err}")

    all_pcaps.sort(key=lambda x: x.get('filename', ''), reverse=False)

    for item in all_pcaps:
        if not item.get('packets') or not item.get('duration'):
            meta_path = os.path.join(app.config['ZEEK_LOGS_FOLDER'], item['pcap_id'], 'metadata.json')
            if os.path.exists(meta_path):
                try:
                    with open(meta_path, 'r') as f:
                        meta = json.load(f)
                        item['packets'] = item['packets'] or meta.get('packets')
                        item['duration'] = item['duration'] or meta.get('duration')
                except Exception:
                    pass

            if item.get('packets') is None:
                conn_log = os.path.join(app.config['ZEEK_LOGS_FOLDER'], item['pcap_id'], 'conn.log')
                if os.path.exists(conn_log):
                    try:
                        with open(conn_log, 'r') as f:
                            count = sum(1 for line in f if not line.startswith('#'))
                            item['packets'] = count
                    except Exception:
                        pass

    return all_pcaps


def _build_sinkhole_pcaps(sinkhole_id, search=''):
    sinkhole_id = int(sinkhole_id)

    if sinkhole_id == 1:
        pcaps = _collect_all_pcaps(search=search)
        return pcaps, {
            'sinkhole_id': 1,
            'sinkhole_name': 'sinkhole 1',
            'sinkhole_count': len(pcaps),
        }

    if sinkhole_id == 2:
        return [], {
            'sinkhole_id': 2,
            'sinkhole_name': 'sinkhole 2',
            'sinkhole_count': 0,
        }

    return [], {
        'sinkhole_id': sinkhole_id,
        'sinkhole_name': f'sinkhole {sinkhole_id}',
        'sinkhole_count': 0,
    }


def _pcap_stats_payload(stats, pcap_id):
    session_timeline = stats.get('time_series', []) or []
    return {
        'total_packets': stats.get('total_packets', 0),
        'total_bytes': stats.get('total_bytes', 0),
        'duration_seconds': stats.get('duration_seconds', 0),
        'start_time_utc': stats.get('start_time_utc'),
        'end_time_utc': stats.get('end_time_utc'),
        'total_connections': stats.get('total_connections', 0),
        'internal_ips_count': len(stats.get('internal_ips') or []),
        'external_ips_count': len(stats.get('external_ips') or []),
        'infected_host': stats.get('infected_host', 'Unknown'),
        'session_timeline': session_timeline,
        'time_series': session_timeline,
    }


def _pcap_overview_payload(stats, pcap_id):
    return {
        'pcap_id': pcap_id,
        'summary': _pcap_stats_payload(stats, pcap_id),
        'traffic_distribution': _pcap_traffic_distribution_payload(stats, pcap_id),
    }


def _take_top(items, limit=10):
    return (items or [])[:limit]


def _collect_infected_hosts_from_pcaps():
    infected_hosts = []
    seen = set()
    for pcap_id in _discover_existing_pcap_ids(app.config['UPLOAD_FOLDER']):
        item = elastic.get_pcap_summary(pcap_id) or {}
        host = (item.get('infected_host') or '').strip()
        if not host or host.lower() == 'unknown' or host in seen:
            continue
        seen.add(host)
        infected_hosts.append({
            'infected_host': host,
            'pcap_id': pcap_id,
        })
    return infected_hosts


def _dashboard_overview_payload():
    global_stats = elastic.get_global_aggregation()
    repo_stats = elastic.get_repository_stats()
    ip_breakdown = elastic.get_ip_breakdown()

    traffic_distribution = {
        'transport': elastic.get_dashboard_breakdown_totals('transport_breakdown'),
        'application': elastic.get_dashboard_breakdown_totals(
            'application_breakdown',
            exclude_labels={'tcp', 'udp', 'icmp', 'unknown_transport'}
        ),
        'directions': elastic.get_dashboard_breakdown_totals('direction_breakdown'),
        'dns_queries': _take_top([
            {'domain': item.get('domain'), 'count': item.get('count', 0)}
            for item in global_stats.get('top_dns_domains', []) or []
        ], 5),
        'urls': _take_top([
            {'url': item.get('domain'), 'count': item.get('count', 0)}
            for item in global_stats.get('top_url_domains', []) or []
        ], 5),
        'ssl_servers': _take_top(elastic.get_dashboard_breakdown_totals('ssl_servers'), 5),
    }

    insights_trends = {
        'top_active_ips': _take_top(global_stats.get('top_active_ips', []), 10),
        'protocol_breakdown': _take_top(global_stats.get('protocol_breakdown', []), 10),
    }

    stats_details = {
        'top_countries': _take_top(ip_breakdown.get('countries', []), 10),
        'top_isps': _take_top(ip_breakdown.get('isps', []), 10),
        'top_cities': _take_top(ip_breakdown.get('cities', []), 10),
        'top_active_ips': _take_top(global_stats.get('top_active_ips', []), 10),
        'internal_ips_count': global_stats.get('total_internal_ips', 0),
        'external_ips_count': global_stats.get('total_external_ips', 0),
        'infected_hosts_count': global_stats.get('total_infected_hosts', 0),
        'infected_hosts': _take_top(_collect_infected_hosts_from_pcaps(), 10),
    }

    summary = {
        'total_pcaps': repo_stats.get('total_pcaps', 0),
        'observed_ips': repo_stats.get('observed_ips', 0),
        'repository_size': repo_stats.get('repository_size', 0),
        'traffic_volume': repo_stats.get('traffic_volume', 0),
        'total_packets': global_stats.get('total_packets', 0),
        'total_bytes': global_stats.get('total_bytes', 0),
        'total_infected_hosts': global_stats.get('total_infected_hosts', 0),
        'total_internal_ips': global_stats.get('total_internal_ips', 0),
        'total_external_ips': global_stats.get('total_external_ips', 0),
        'total_dns_domains': global_stats.get('total_dns_domains', 0),
        'total_url_domains': global_stats.get('total_url_domains', 0),
        'total_protocols': global_stats.get('total_protocols', 0),
    }

    return {
        'summary': summary,
        'traffic_distribution': traffic_distribution,
        'insights_trends': insights_trends,
        'stats_details': stats_details,
    }


def _dashboard_insights_payload():
    global_stats = elastic.get_global_aggregation()
    ip_breakdown = elastic.get_ip_breakdown()
    return {
        'insights_trends': {
            'top_active_ips': _take_top(global_stats.get('top_active_ips', []), 10),
            'protocol_breakdown': _take_top(global_stats.get('protocol_breakdown', []), 10),
        },
        'stats_details': {
            'top_countries': _take_top(ip_breakdown.get('countries', []), 10),
            'top_isps': _take_top(ip_breakdown.get('isps', []), 10),
            'top_cities': _take_top(ip_breakdown.get('cities', []), 10),
            'top_active_ips': _take_top(global_stats.get('top_active_ips', []), 10),
            'internal_ips_count': global_stats.get('total_internal_ips', 0),
            'external_ips_count': global_stats.get('total_external_ips', 0),
        },
    }


def _pcap_insights_payload(stats):
    return {
        'internal_ips': stats.get('internal_ips', []) or [],
        'external_ips': stats.get('external_ips', []) or [],
        'protocols': stats.get('protocols', []) or [],
        'ports': stats.get('ports', []) or [],
        'dns_queries': stats.get('dns_queries', []) or [],
        'domains': stats.get('top_dns_domains', []) or [],
        'urls': stats.get('top_url_domains', []) or [],
        'files_and_payloads': stats.get('file_payloads', []) or [],
        'user_agents': stats.get('user_agents', []) or [],
    }


def _pcap_traffic_distribution_payload(stats, pcap_id):
    return {
        'pcap_id': pcap_id,
        'transport': _stats_counter_rows(stats, 'transport_breakdown', 'protocol', 'packets'),
        'application': _stats_counter_rows(
            stats,
            'application_breakdown',
            'protocol',
            'packets',
            exclude_labels={'tcp', 'udp', 'icmp', 'unknown_transport'}
        ),
        'directions': _stats_counter_rows(stats, 'direction_breakdown', 'direction', 'packets'),
        'dns_queries': [
            {'domain': item.get('label'), 'count': item.get('value', 0)}
            for item in (stats.get('top_dns_domains', []) or [])[:5]
        ],
        'urls': [
            {'url': item.get('label'), 'count': item.get('value', 0)}
            for item in (stats.get('top_url_domains', []) or [])[:5]
        ],
        'ssl_servers': [
            {'ssl_server': item.get('label'), 'count': item.get('value', 0)}
            for item in (stats.get('top_ssl_servers', []) or [])[:5]
        ],
    }


# ---------------- STATS ----------------
def get_stats():
    try:
        requested_pcap_id = request.args.get('pcap_id') or None
        stats = build_dashboard_stats(
            app.config['UPLOAD_FOLDER'],
            app.config['ZEEK_LOGS_FOLDER'],
            requested_pcap_id,
            force_rebuild=bool(requested_pcap_id)
        )
        stats.update(get_site_status_context(es, None))
        return api_response(data=stats)
    except Exception as error:
        return api_response(data=None, success=False, error=str(error)), 500


# ---------------- RECENT LOGS ----------------
@app.route('/api/recent-logs/<log_type>')
def get_recent_logs(log_type):
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        timeline = request.args.get('timeline')
        pcap_id = request.args.get('pcap_id')

        result = {'logs': [], 'page': page, 'per_page': per_page, 'total': 0, 'total_pages': 1}

        if es:
            try:
                result = elastic.get_recent_logs_from_es(
                    log_type=log_type,
                    timeline=timeline,
                    page=page,
                    per_page=per_page,
                    pcap_id=pcap_id
                )
            except Exception as error:
                print(f"ES search failed, fallback to files: {error}")
                result = build_recent_logs(
                    app.config['ZEEK_LOGS_FOLDER'],
                    log_type,
                    page=page,
                    per_page=per_page,
                    timeline=timeline
                )
        else:
            result = build_recent_logs(
                app.config['ZEEK_LOGS_FOLDER'],
                log_type,
                page=page,
                per_page=per_page,
                timeline=timeline
            )

        return api_response(
            data=result.get('logs', []),
            page=result.get('page'),
            per_page=result.get('per_page'),
            total=result.get('total'),
            total_pages=result.get('total_pages')
        )

    except Exception as e:
        return api_response(data=[], success=False, error=str(e)), 500


# ---------------- PCAP APIs ----------------

# Uniform overview API:
# - dashboard scope when pcap_id is absent
# - per-PCAP scope when pcap_id is present
@app.route('/api/overview')
@app.route('/api/dashboard/overview')
@app.route('/api/pcaps/<pcap_id>/summary')
def get_overview(pcap_id=None):
    try:
        scoped_pcap_id = pcap_id or request.args.get('pcap_id')
        if scoped_pcap_id:
            data = _load_pcap_stats(scoped_pcap_id, force_rebuild=True)
            if data and data.get('file_id') == scoped_pcap_id:
                return api_response(data=_pcap_overview_payload(data, scoped_pcap_id))
            return api_response(data=None, success=False, error=f'No analysis found for {scoped_pcap_id}'), 404

        return api_response(data=_dashboard_overview_payload())
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


# Uniform insights API:
# - dashboard scope when pcap_id is absent
# - per-PCAP scope when pcap_id is present
@app.route('/api/insights')
@app.route('/api/pcaps/<pcap_id>/insights')
def get_insights(pcap_id=None):
    try:
        scoped_pcap_id = pcap_id or request.args.get('pcap_id')
        if scoped_pcap_id:
            stats = _load_pcap_stats(scoped_pcap_id, force_rebuild=False)
            if not stats or stats.get('file_id') != scoped_pcap_id:
                return api_response(data=None, success=False, error=f'No analysis found for {scoped_pcap_id}'), 404

            insights = _pcap_insights_payload(stats)
            return api_response(data={
                'pcap_insights': {
                    'internal_ips': insights['internal_ips'],
                    'external_ips': insights['external_ips'],
                    'protocols': insights['protocols'],
                    'ports': insights['ports'],
                    'dns_queries': insights['dns_queries'],
                    'domains': insights['domains'],
                    'urls': insights['urls'],
                    'files_and_payloads': insights['files_and_payloads'],
                    'user_agents': insights['user_agents'],
                }
            })

        return api_response(data=_dashboard_insights_payload())
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/pcaps/<pcap_id>/connections')
def get_pcap_connections(pcap_id):
    try:
        page = request.args.get('page', 1, type=int)
        timeline = request.args.get('timeline')
        per_page = 40

        result = None
        if es:
            try:
                result = elastic.get_recent_logs_from_es(
                    log_type='conn',
                    timeline=timeline,
                    page=page,
                    per_page=per_page,
                    pcap_id=pcap_id
                )
            except Exception:
                result = None

        if not result:
            result = _load_local_connections_page(
                app.config['ZEEK_LOGS_FOLDER'],
                pcap_id,
                page=page,
                per_page=per_page,
                timeline=timeline
            )

        sanitized_logs = [_normalize_recent_connection_row(log) for log in result.get('logs', []) or []]

        return api_response(
            data=sanitized_logs,
            page=result.get('page'),
            per_page=result.get('per_page'),
            total=result.get('total'),
            total_pages=result.get('total_pages')
        )
    except Exception as e:
        return api_response(data=[], success=False, error=str(e)), 500


@app.route('/api/reports/geo')
def get_geo_report():
    try:
        pcap_id = request.args.get('pcap_id')
        data = elastic.get_geo_aggregation(pcap_id)
        
        # If no pcap_id, also include global repository stats
        if not pcap_id:
            global_stats = elastic.get_global_aggregation()
            return api_response(data=data, meta={"global_stats": global_stats})
                
        return api_response(data=data)
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/reports/details/<report_type>/<report_value>')
def get_report_details_path(report_type, report_value):
    data = elastic.get_report_details(report_type, report_value)
    return api_response(data=data, meta={
        "total_unique_ips": len(data),
        "report_type": report_type,
        "filter_value": report_value
    })


def get_dashboard():
    try:
        return api_response(data=_dashboard_overview_payload())
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/stats/global')
def get_global_stats():
    try:
        return api_response(data=_dashboard_overview_payload())
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/reports/isp')
def get_pcap_report_isp():
    try:
        pcap_id = request.args.get('pcap_id')
        if not pcap_id:
            return api_response(data=None, success=False, error='pcap_id is required'), 400
        data = _build_flat_ip_group_list(pcap_id, 'isp', 'isps', 'isp')
        return api_response(data={'pcap_id': pcap_id, 'items': data})
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/reports/country')
def get_pcap_report_country():
    try:
        pcap_id = request.args.get('pcap_id')
        if not pcap_id:
            return api_response(data=None, success=False, error='pcap_id is required'), 400
        data = _build_flat_ip_group_list(pcap_id, 'country', 'countries', 'country')
        return api_response(data={'pcap_id': pcap_id, 'items': data})
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/reports/city')
def get_pcap_report_city():
    try:
        pcap_id = request.args.get('pcap_id')
        if not pcap_id:
            return api_response(data=None, success=False, error='pcap_id is required'), 400
        data = _build_flat_ip_group_list(pcap_id, 'city', 'cities', 'city')
        return api_response(data={'pcap_id': pcap_id, 'items': data})
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/reports/country/isp')
def get_pcap_report_country_isp():
    try:
        pcap_id = request.args.get('pcap_id')
        if not pcap_id:
            return api_response(data=None, success=False, error='pcap_id is required'), 400
        data = _build_nested_ip_groups(pcap_id, 'country', 'isp', 'country', 'isp')
        return api_response(data={'pcap_id': pcap_id, 'items': data})
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/reports/country/city')
def get_pcap_report_country_city():
    try:
        pcap_id = request.args.get('pcap_id')
        if not pcap_id:
            return api_response(data=None, success=False, error='pcap_id is required'), 400
        data = _build_nested_ip_groups(pcap_id, 'country', 'city', 'country', 'city')
        return api_response(data={'pcap_id': pcap_id, 'items': data})
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


# PCAP grid endpoint
@app.route('/api/pcaps')
@app.route('/api/pcaps/<int:sinkhole_id>')
def get_pcaps(sinkhole_id=1):
    try:
        search = request.args.get('search', '', type=str).lower()
        if sinkhole_id == 1:
            page_data, _ = _build_sinkhole_pcaps(1, search=search)
        else:
            page_data, _ = _build_sinkhole_pcaps(sinkhole_id, search=search)
        return api_response(
            data=page_data,
            total=len(page_data),
            meta={"repository_stats": elastic.get_repository_stats()}
        )
    except Exception as e:
        print(f"Error in /api/pcaps/{sinkhole_id}: {e}")
        return api_response(data=[], success=False, error=str(e)), 500


@app.route('/api/pcaps/set/<int:sinkhole_id>')
def get_pcaps_page(sinkhole_id):
    try:
        search = request.args.get('search', '', type=str).lower()
        page_data, meta = _build_sinkhole_pcaps(sinkhole_id, search=search)
        return api_response(
            data=page_data,
            meta={
                **meta,
            }
        )
    except Exception as e:
        print(f"Error in /api/pcaps/set/{sinkhole_id}: {e}")
        return api_response(data=[], success=False, error=str(e)), 500


# ---------------- IP SCAN ----------------
# ---------------- IP SCAN ----------------
@app.route('/api/ip/scan/<ip_address>')
def scan_ip_details(ip_address):
    try:
        # PURE FETCH: No waiting, just return what is in ES
        data = scanner.get_scan_data(ip_address)
        if data:
            return api_response(data=data)

        # Fallback: Enqueue a background scan if it doesn't exist, but don't wait
        scanner.enqueue_ip_intelligence_scan(ip_address, source="on_demand_click")
        
        return api_response(
            data=None,
            success=False,
            error=f'Deep Intelligence is being gathered for {ip_address}.'
        ), 202
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/ip-intelligence/backfill', methods=['POST'])
def backfill_ip_intelligence():
    try:
        result = _backfill_existing_ip_intelligence()
        return api_response(data=result)
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/map')
def get_map_data():
    try:
        level = request.args.get('level')
        if not level:
            return api_response(data=None, success=False, error='level is required'), 400

        data = elastic.get_country_city_map(level=level)
        if not data:
            return api_response(data=None, success=False, error=f'Unsupported or empty level: {level}'), 404

        return api_response(data=data)
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/map/external-ips')
def get_global_map_data():
    try:
        data = elastic.get_country_city_map(level='country')
        rows = data.get('data', []) if isinstance(data, dict) else []
        return api_response(data=data, meta={
            "total_countries": len(rows)
        })
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/map/external-ips/export')
def export_external_ips():
    try:
        rows = elastic.get_all_external_ips()
        response = api_response(
            data=rows,
            meta={
                "total_ips": len(rows)
            }
        )
        response.headers['Content-Disposition'] = 'attachment; filename=external_ips.json'
        return response
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


# ---------------- MAIN ----------------
if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['ZEEK_LOGS_FOLDER'], exist_ok=True)

    elastic.create_pcap_index()
    scanner.create_scan_index()
    # Dampened backfill: We don't start the aggressive thread on every boot
    # _start_backfill_thread()

    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '8005')), debug=False, threaded=True)
