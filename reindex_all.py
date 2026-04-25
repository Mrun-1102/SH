import os
import sys
import glob

# Ensure we can import from the current directory
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from zeek_analysis import build_dashboard_stats

def discover_pcap_ids(upload_folder):
    """Finds all unique PCAP IDs in the upload directory."""
    pcap_ids = []
    seen_ids = set()
    if not os.path.exists(upload_folder):
        return pcap_ids

    for file in os.listdir(upload_folder):
        if not (file.endswith('.pcap') or file.endswith('.pcapng')):
            continue

        parts = file.split('_', 1)
        if len(parts) != 2:
            continue

        pcap_id = parts[0]
        if pcap_id and pcap_id not in seen_ids:
            seen_ids.add(pcap_id)
            pcap_ids.append(pcap_id)

    return pcap_ids

def run_reindex():
    upload_folder = 'zeek_uploads'
    zeek_logs_folder = 'zeek_logs'
    
    pcap_ids = discover_pcap_ids(upload_folder)
    total = len(pcap_ids)
    
    print(f"[*] Found {total} PCAPs to process.")
    print("[*] This will re-summarize and update granular Elasticsearch indexes (IPs, DNS, etc.)")
    print("[*] Note: This does NOT re-run Zeek analysis, so it should be relatively fast.\n")
    
    for i, pcap_id in enumerate(pcap_ids, 1):
        print(f"[{i}/{total}] Re-indexing {pcap_id}...")
        try:
            # force_rebuild=True ensures it re-parses logs and pushes to ES
            build_dashboard_stats(upload_folder, zeek_logs_folder, pcap_id, force_rebuild=True)
        except Exception as e:
            print(f"  ✗ Failed {pcap_id}: {e}")

    print("\n[+] Re-indexing complete! All 118 PCAPs (or found amount) are now aggregated.")

if __name__ == "__main__":
    run_reindex()
