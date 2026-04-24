import os
import elastic
from zeek_analysis import build_dashboard_stats

def migrate_all():
    print(" Starting Granular Data Migration...")
    
    # Initialize ES and Indexes
    elastic.create_granular_indexes()
    
    app_root = os.path.abspath(os.path.dirname(__file__))
    upload_folder = os.path.join(app_root, 'zeek_uploads')
    zeek_logs_folder = os.path.join(app_root, 'zeek_logs')

    if not os.path.exists(upload_folder):
        print("✗ Upload folder not found.")
        return

    # In this environment, pcap_ids are the first 8 chars of filenames
    files = [f for f in os.listdir(upload_folder) if f.endswith('.pcap') or f.endswith('.pcapng')]
    total = len(files)
    print(f"📦 Found {total} files to re-index.")

    for i, filename in enumerate(files):
        pcap_id = filename.split('_')[0]
        
        print(f"[{i+1}/{total}] Processing: {filename}...")
        try:
            stats = build_dashboard_stats(upload_folder, zeek_logs_folder, pcap_id, force_rebuild=True)
            
            if not stats or not stats.get('file_id'):
                continue

            summary_data = {
                'total_packets': stats.get('summary', {}).get('total_packets', 0),
                'duration_seconds': stats.get('summary', {}).get('duration_seconds', 0),
                'total_bytes': stats.get('summary', {}).get('total_bytes', 0),
                'file_size': os.path.getsize(os.path.join(upload_folder, filename)),
                'unique_ips': len(stats.get('raw_external_ips', [])),
                'unique_domains': len(stats.get('top_dns_domains', [])) + len(stats.get('top_url_domains', []))
            }

            ips_data = []
            for ip_obj in stats.get('raw_external_ips', []):
                ip_addr = ip_obj.get('ip')
                if not ip_addr or ip_addr == 'Unknown' or '.' not in str(ip_addr):
                    continue

                ips_data.append({
                    'ip': str(ip_addr),
                    'packet_count': ip_obj.get('packet_count', 0),
                    'country': ip_obj.get('country'),
                    'city': ip_obj.get('city'),
                    'isp': ip_obj.get('isp'),
                    'latitude': ip_obj.get('latitude'),
                    'longitude': ip_obj.get('longitude'),
                    'is_internal': False
                })

            dns_data = []
            for d_obj in stats.get('top_dns_domains', []):
                name = list(d_obj.keys())[0] if isinstance(d_obj, dict) else str(d_obj)
                count = d_obj[name] if isinstance(d_obj, dict) else 1
                dns_data.append({'domain': name, 'type': 'dns', 'count': count})
            
            for u_obj in stats.get('top_url_domains', []):
                name = list(u_obj.keys())[0] if isinstance(u_obj, dict) else str(u_obj)
                count = u_obj[name] if isinstance(u_obj, dict) else 1
                dns_data.append({'domain': name, 'type': 'http', 'count': count})

            print(f"  ↪ Summary: {len(summary_data)}, IPs: {len(ips_data)}, DNS: {len(dns_data)}")

            success = elastic.bulk_index_granular_data(
                pcap_id, 
                stats.get('file_name', filename), 
                summary_data, 
                ips_data, 
                dns_data
            )
            print(f"  ✓ Indexed {success} records.")

        except Exception as e:
            print(f"  ✗ Error processing {filename}: {e}")

    print("✅ Migration Complete.")

if __name__ == "__main__":
    migrate_all()
