import os
import json
from elastic import get_es
from zeek_analysis import parse_zeek_log, build_dashboard_stats, index_to_elasticsearch
import scanner

def reindex_all():
    es = get_es()
    logs_dir = '/home/esec/pcap-analysis-master/flask-app/zeek_logs'
    upload_dir = '/home/esec/pcap-analysis-master/flask-app/zeek_uploads'
    
    pcap_ids = [d for d in os.listdir(logs_dir) if os.path.isdir(os.path.join(logs_dir, d))]
    print(f"Found {len(pcap_ids)} captures to re-index...")
    
    for pcap_id in pcap_ids:
        pcap_path = os.path.join(logs_dir, pcap_id)
        print(f"Processing ID: {pcap_id}")
        
        # 1. Index all .log files
        for log_file in os.listdir(pcap_path):
            if log_file.endswith('.log'):
                log_type = log_file.replace('.log', '')
                full_path = os.path.join(pcap_path, log_file)
                logs = parse_zeek_log(full_path)
                if logs:
                    success, msg = index_to_elasticsearch(es, None, log_type, logs, pcap_id)
                    if success:
                        print(f"  - Indexed {len(logs)} records from {log_file}")
                    else:
                        print(f"  - Error indexing {log_file}: {msg}")
        
        # 2. Rebuild the dashboard summary index
        try:
            stats = build_dashboard_stats(upload_dir, logs_dir, pcap_id=pcap_id, force_rebuild=True)
            print(f"  - Dashboard summary rebuilt for {pcap_id}")
            
            # 3. Queue IP intelligence scans
            ips = stats.get('external_ips') or stats.get('raw_external_ips') or []
            if ips:
                scanner.enqueue_ip_intelligence_scans(ips, pcap_id=pcap_id, source='recovery_reindex')
                print(f"  - Queued {len(ips)} IP scans")
        except Exception as e:
            print(f"  - Failed to rebuild summary for {pcap_id}: {e}")

if __name__ == "__main__":
    reindex_all()
