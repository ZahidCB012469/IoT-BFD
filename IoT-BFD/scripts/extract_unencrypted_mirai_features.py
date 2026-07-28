#!/usr/bin/env python3
"""
Extract features from UNENCRYPTED Mirai/Torii PCAPs using same logic as encrypted extraction

This creates a fair comparison:
- Train on unencrypted features extracted with 120s timeout
- Test on encrypted features extracted with 120s timeout
- Same traffic, same extraction logic, only difference is encryption
"""

import os
import pandas as pd
import numpy as np
from scapy.all import *
from scapy.layers.inet import IP, TCP
from collections import defaultdict

# Use EXACT same logic as generate_encrypted_c2.py
FLOW_TIMEOUT = 120.0

def extract_features_from_pcap(pcap_path, max_packets=None):
    """Extract flow features with 120s timeout (SAME as encrypted extraction)"""
    
    print(f"\n Processing: {os.path.basename(pcap_path)}")
    file_size_mb = os.path.getsize(pcap_path) / (1024*1024)
    print(f"   Size: {file_size_mb:.1f} MB")
    
    # For large files, process in chunks
    if file_size_mb > 500:
        print(f"     Large file detected - processing in chunks of 50,000 packets")
    
    flows = defaultdict(lambda: {'fwd': [], 'bwd': [], 'start_time': None, 'last_time': None})
    completed_flows = []
    packet_count = 0
    
    try:
        reader = PcapReader(pcap_path)
    except Exception as e:
        print(f" Error: {e}")
        return pd.DataFrame()
    
    for packet in reader:
        packet_count += 1
        
        # Progress indicator for large files
        if file_size_mb > 500 and packet_count % 10000 == 0:
            print(f"    Processed {packet_count:,} packets, {len(completed_flows):,} flows completed...")
        
        # Stop if max_packets limit reached (for testing/memory management)
        if max_packets and packet_count >= max_packets:
            print(f"     Reached packet limit ({max_packets:,}), stopping...")
            break
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            proto = 'TCP'
            
            # Canonical flow key
            if (src_ip, src_port) < (dst_ip, dst_port):
                flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
                direction = 'fwd'
            else:
                flow_key = (dst_ip, src_ip, dst_port, src_port, proto)
                direction = 'bwd'
            
            timestamp = float(packet.time)
            length = len(packet)
            
            # Check flow timeout
            flow = flows[flow_key]
            if flow['start_time'] is None:
                flow['start_time'] = timestamp
                flow['last_time'] = timestamp
            elif timestamp - flow['last_time'] > FLOW_TIMEOUT:
                # Flow timed out - save it and start new flow
                completed_flows.append((flow_key, dict(flow)))
                flows[flow_key] = {'fwd': [], 'bwd': [], 'start_time': timestamp, 'last_time': timestamp}
                flow = flows[flow_key]
            else:
                flow['last_time'] = timestamp
            
            flow[direction].append({
                'timestamp': timestamp,
                'length': length
            })
    
    # Add remaining active flows
    for flow_key, flow_data in flows.items():
        if len(flow_data['fwd']) > 0 or len(flow_data['bwd']) > 0:
            completed_flows.append((flow_key, flow_data))
    
    reader.close()
    print(f"    Total packets processed: {packet_count:,}")
    print(f"    Total flows found: {len(completed_flows):,}")
    
    # Process flows into features
    dataset = []
    
    for flow_key, flow_data in completed_flows:
        src_ip, dst_ip, src_port, dst_port, proto = flow_key
        
        fwd_packets = flow_data['fwd']
        bwd_packets = flow_data['bwd']
        
        if len(fwd_packets) == 0 and len(bwd_packets) == 0:
            continue
        
        # SAME filters as encrypted extraction
        if len(fwd_packets) + len(bwd_packets) < 3:
            continue
        
        if len(fwd_packets) + len(bwd_packets) > 5000:
            continue
        
        all_packets = fwd_packets + bwd_packets
        all_packets.sort(key=lambda x: x['timestamp'])
        
        timestamps = [p['timestamp'] for p in all_packets]
        fwd_lengths = [p['length'] for p in fwd_packets]
        bwd_lengths = [p['length'] for p in bwd_packets]
        all_lengths = fwd_lengths + bwd_lengths
        
        duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0
        
        iats = np.diff(timestamps)
        iat_mean = np.mean(iats) if len(iats) > 0 else 0
        iat_min = np.min(iats) if len(iats) > 0 else 0
        iat_max = np.max(iats) if len(iats) > 0 else 0
        iat_std = np.std(iats) if len(iats) > 0 else 0
        
        pkt_mean = np.mean(all_lengths)
        pkt_min = np.min(all_lengths)
        pkt_max = np.max(all_lengths)
        pkt_std = np.std(all_lengths)
        
        total_packets = len(fwd_packets) + len(bwd_packets)
        directionality_ratio = len(fwd_packets) / total_packets if total_packets > 0 else 1.0
        flow_periodicity = iat_std / iat_mean if iat_mean > 0 else 0
        
        row = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': proto,
            'dst_port': dst_port,
            'flow_duration': duration,
            'packet_count_fwd': len(fwd_packets),
            'packet_count_bwd': len(bwd_packets),
            'byte_count_fwd': sum(fwd_lengths),
            'byte_count_bwd': sum(bwd_lengths) if bwd_lengths else 0,
            'iat_mean': iat_mean,
            'iat_min': iat_min,
            'iat_max': iat_max,
            'iat_std': iat_std,
            'packet_size_mean': pkt_mean,
            'packet_size_min': pkt_min,
            'packet_size_max': pkt_max,
            'packet_size_std': pkt_std,
            'flow_periodicity': flow_periodicity,
            'directionality_ratio': directionality_ratio,
            'tcp_flags': '',
            'tcp_window_size_mean': 0,
            'ip_ttl_mean': 0,
            'unique_endpoints': 1,
            'label': 'C&C'  # Mark as malicious C2
        }
        
        dataset.append(row)
    
    df = pd.DataFrame(dataset)
    
    if len(df) > 0:
        # SAME outlier filtering
        before_filter = len(df)
        df = df[df['iat_mean'] < 1000]
        df = df[df['flow_duration'] < 7200]
        print(f"    After filtering: {len(df)} flows")
    
    return df

def main():
    print("="*70)
    print("EXTRACT UNENCRYPTED MIRAI/TORII FEATURES")
    print("="*70)
    print("\nThis extracts features from ORIGINAL PCAPs using SAME logic")
    print("as the encrypted extraction (120s timeout, same filters).")
    print("\nPurpose: Create fair training set for encrypted C2 validation")
    
    # Define PCAP locations
    pcap_main_dir = "/home/ioht22/contiki-ng/FYP/pcaps"
    pcap_mirai_dir = "/home/ioht22/contiki-ng/FYP/pcaps/miraipcaps"
    
    # Process ALL Mirai/Torii PCAPs (including the large linuxmirai.pcap)
    # Format: (filename, directory, max_packets)
    pcaps_to_process = [
        ('mirai1.pcap', pcap_mirai_dir, None),       # 120.5 MB - process fully
        ('mirai34.pcap', pcap_main_dir, None),       # 120.5 MB - process fully  
        ('torii1.pcap', pcap_mirai_dir, None),       # 3.9 MB - process fully
        ('torii2.pcap', pcap_mirai_dir, None),       # 3.9 MB - process fully
        ('linuxmirai.pcap', pcap_main_dir, 500000)   # 896 MB - limit to 500k packets for memory
    ]
    
    all_flows = []
    
    for pcap_file, pcap_dir, max_packets in pcaps_to_process:
        pcap_path = os.path.join(pcap_dir, pcap_file)
        if os.path.exists(pcap_path):
            print(f"\n{'='*70}")
            df = extract_features_from_pcap(pcap_path, max_packets=max_packets)
            if len(df) > 0:
                all_flows.append(df)
                print(f"    Extracted {len(df):,} flows from {pcap_file}")
            else:
                print(f"     No flows extracted from {pcap_file}")
        else:
            print(f"\n     File not found: {pcap_path}")
    
    if len(all_flows) > 0:
        df_combined = pd.concat(all_flows, ignore_index=True)
        
        output_path = "/home/ioht22/contiki-ng/FYP/pcaps/finalcsv/unencrypted_mirai_features.csv"
        df_combined.to_csv(output_path, index=False)
        
        print("\n" + "="*70)
        print(" EXTRACTION COMPLETE")
        print("="*70)
        print(f"\n Total unencrypted C2 flows: {len(df_combined)}")
        print(f" Saved to: {output_path}")
        
        print("\n Feature Statistics:")
        key_features = ['iat_mean', 'iat_std', 'flow_periodicity', 'directionality_ratio',
                       'packet_count_fwd', 'packet_count_bwd']
        print(df_combined[key_features].describe())
        
        print("\n" + "="*70)
        print("NEXT STEPS")
        print("="*70)
        print("\n1. Train model on these unencrypted features + benign IoT")
        print("2. Test on encrypted_c2_features.csv (same PCAPs, encrypted)")
        print("3. This gives FAIR comparison: same traffic, only encryption differs")
        print("\n Note: linuxmirai.pcap limited to 500k packets for memory efficiency")
        print("   (still provides diverse training samples)")
        print("\n This will properly validate encrypted C2 detection!")
        
    else:
        print("\n No flows extracted!")

if __name__ == "__main__":
    main()
