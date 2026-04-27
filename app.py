from flask import Flask, render_template, request, jsonify
import hashlib
import json
import os
import shutil
import threading
import urllib3

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


# ---------------- STATS ----------------
@app.route('/api/stats')
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
                result = build_recent_logs(app.config['ZEEK_LOGS_FOLDER'], log_type, page=page, per_page=per_page)
        else:
            result = build_recent_logs(app.config['ZEEK_LOGS_FOLDER'], log_type, page=page, per_page=per_page)

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

# Use build_dashboard_stats for full summary
@app.route('/api/pcap/<pcap_id>')
def get_pcap_analysis(pcap_id):
    try:
        data = build_dashboard_stats(
            app.config['UPLOAD_FOLDER'],
            app.config['ZEEK_LOGS_FOLDER'],
            pcap_id=pcap_id,
            force_rebuild=True
        )
        if data and data.get('file_id') == pcap_id:
            response_data = dict(data)
            # Remove redundant or unused fields
            response_data.pop('recent_connections', None)
            response_data.pop('file_payloads', None)
            
            # Add the new 'Files and Payloads' intelligence (cleaning up redundant IDs)
            payloads = elastic.get_payloads_summary(pcap_id)
            for p in payloads: p.pop('pcap_id', None)
            
            response_data['files_and_payloads'] = payloads
            
            return api_response(data=response_data)
        return api_response(data=None, success=False, error=f'No analysis found for {pcap_id}'), 404
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/pcap/latest')
def get_latest_pcap_analysis():
    try:
        data = elastic.get_latest_dashboard_document()
        if data:
            response_data = dict(data)
            # Remove redundant fields
            response_data.pop('recent_connections', None)
            response_data.pop('file_payloads', None)
            
            pcap_id = response_data.get('file_id')
            if pcap_id:
                payloads = elastic.get_payloads_summary(pcap_id)
                for p in payloads: p.pop('pcap_id', None)
                response_data['files_and_payloads'] = payloads
            else:
                response_data['files_and_payloads'] = []
            
            return api_response(data=response_data)
        return api_response(data=None, success=False, error='No dashboard documents found in Elasticsearch'), 404
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/pcap/<pcap_id>/connections')
def get_pcap_connections(pcap_id):
    try:
        limit = request.args.get('limit', 100, type=int)
        safe_limit = max(1, min(limit, 500))
        result = elastic.get_recent_logs_from_es(
            log_type='conn',
            page=1,
            per_page=safe_limit,
            pcap_id=pcap_id
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


@app.route('/api/pcap/<pcap_id>/files')
def get_pcap_files(pcap_id):
    try:
        data = _load_local_file_payloads(app.config['ZEEK_LOGS_FOLDER'], pcap_id)
        return api_response(data=data)
    except Exception as e:
        return api_response(data=[], success=False, error=str(e)), 500


@app.route('/api/pcap/all')
def get_all_pcap_analyses():
    try:
        data = elastic.get_all_pcap_analyses()
        return api_response(data=data, total=len(data))
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/reports/geo')
def get_geo_report():
    try:
        pcap_id = request.args.get('pcap_id')
        data = elastic.get_geo_aggregation(pcap_id)
        
        # If no pcap_id, also include global repository stats
        if not pcap_id:
            global_stats = elastic.get_global_aggregation()
            if data and isinstance(data, dict):
                data['global_stats'] = global_stats
                
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


@app.route('/api/stats/global')
def get_global_stats():
    try:
        data = elastic.get_global_aggregation()
        return api_response(data=data)
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


# Paginated PCAP endpoint for library
@app.route('/api/pcaps')
def get_pcaps():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 12, type=int)
        search = request.args.get('search', '', type=str).lower()
        
        all_pcaps = []
        seen_ids = set()  # Track unique pcap_ids to avoid duplicates
        
        # Always read from disk first (primary source of truth)
        upload_folder = app.config['UPLOAD_FOLDER']
        if os.path.exists(upload_folder):
            for file in os.listdir(upload_folder):
                filepath = os.path.join(upload_folder, file)
                if os.path.isfile(filepath) and (file.endswith('.pcap') or file.endswith('.pcapng')):
                    # Extract pcap_id from filename (format: {pcap_id}_{filename})
                    parts = file.split('_', 1)
                    if len(parts) == 2:
                        pcap_id, filename = parts[0], parts[1]
                        
                        # Skip if already seen (deduplication)
                        if pcap_id in seen_ids:
                            continue
                        seen_ids.add(pcap_id)
                        
                        # Apply search filter
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
        
        # Try to enrich with Elasticsearch data
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
                
                # Update disk records with ES data
                for item in all_pcaps:
                    if item['pcap_id'] in es_data:
                        item['packets'] = item['packets'] or es_data[item['pcap_id']].get('packets')
                        item['duration'] = item['duration'] or es_data[item['pcap_id']].get('duration')
                        item['ip_count'] = es_data[item['pcap_id']].get('ip_count', 0)
            except Exception as es_err:
                print(f"ES enrichment failed: {es_err}")
        
        # Sort alphabetically by filename
        all_pcaps.sort(key=lambda x: x.get('filename', ''), reverse=False)
        
        # Pagination
        total = len(all_pcaps)
        total_pages = (total + per_page - 1) // per_page if per_page > 0 else 1
        page = max(1, min(page, total_pages))
        
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        page_data = all_pcaps[start_idx:end_idx]
        
        # Enrich page data with metadata
        for item in page_data:
            if not item.get('packets') or not item.get('duration'):
                meta_path = os.path.join(app.config['ZEEK_LOGS_FOLDER'], item['pcap_id'], 'metadata.json')
                if os.path.exists(meta_path):
                    try:
                        with open(meta_path, 'r') as f:
                            meta = json.load(f)
                            item['packets'] = item['packets'] or meta.get('packets')
                            item['duration'] = item['duration'] or meta.get('duration')
                    except: pass
                
                # Fallback: count conn.log entries
                if item.get('packets') is None:
                    conn_log = os.path.join(app.config['ZEEK_LOGS_FOLDER'], item['pcap_id'], 'conn.log')
                    if os.path.exists(conn_log):
                        try:
                            with open(conn_log, 'r') as f:
                                count = sum(1 for line in f if not line.startswith('#'))
                                item['packets'] = count
                        except: pass

        return api_response(
            data=page_data,
            page=page,
            per_page=per_page,
            total=total,
            total_pages=total_pages,
            meta={"repository_stats": elastic.get_repository_stats()}
        )
    except Exception as e:
        print(f"Error in /api/pcaps: {e}")
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


@app.route('/api/map/external-ips')
def get_global_map_data():
    try:
        precision = request.args.get('precision', 3, type=int)
        # Safe range for Geohash precision is 1-12. 3 is roughly 150km, 5 is 5km.
        safe_precision = max(1, min(precision, 12))
        
        data = elastic.get_geo_grid_aggregation(precision=safe_precision)
        return api_response(data=data, meta={
            "total_clusters": len(data),
            "precision": safe_precision
        })
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

    app.run(host='0.0.0.0', debug=True, use_reloader=False, port=8003)
