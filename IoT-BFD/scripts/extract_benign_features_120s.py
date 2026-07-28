import os
import csv
import pandas as pd
from collections import defaultdict
from scapy.all import PcapReader, IP, TCP, UDP
import time
import math

# Configuration
PCAP_DIR = "/home/ioht22/contiki-ng/FYP/benign pcaps"
OUTPUT_FILE = "dataset_paper/benign_features_120s.csv"
FLOW_TIMEOUT = 120.0  # 120 seconds timeout precisely matching C2

devices = [
    {
        'name': 'Somfy Doorlock 1',
        'filename': 'somfy/2019-07-03-16-41-09-192.168.1.158.pcap',
        'target_flows': 150,  
    },
    {
        'name': 'Somfy Doorlock 2',
        'filename': 'somfy/2019-07-04-16-41-10-192.168.1.158.pcap',
        'target_flows': 150, 
    },
    {
        'name': 'Somfy Doorlock 3',
        'filename': 'somfy/2019-07-05-16-41-14-192.168.1.158.pcap',
        'target_flows': 150, 
    },
    {
        'name': 'Somfy Doorlock 4',
        'filename': 'somfy/2019-07-06-16-41-17-192.168.1.158.pcap',
        'target_flows': 150, 
    },
    {
        'name': 'Somfy Gateway',
        'filename': 'somfy/2019-07-03-15-15-47-first_start_somfy_gateway.pcap',
        'target_flows': 150,  
    },
    {
        'name': 'Somfy Doorlock 5',
        'filename': 'somfy/2019-07-07-16-41-19-192.168.1.158.pcap',
        'target_flows': 150, 
    },
    {
        'name': 'Philips HUE',
        'filename': '2018-10-25-14-06-32-192.168.1.132.pcap',
        'target_flows': 700, 
    },
    {
        'name': 'Amazon Echo',
        'filename': '../pcaps/iot23/amazon_echo_benign.pcap',
        'target_flows': 791, 
    }
]

def calculate_iat(packets):
    if len(packets) < 2:
        return 0, 0, 0, 0
    tstamps = [p.time for p in packets]
    iats = [float(tstamps[i] - tstamps[i-1]) for i in range(1, len(tstamps))]
    mean_iat = sum(iats) / len(iats)
    max_iat = max(iats)
    min_iat = min(iats)
    std_iat = math.sqrt(sum((x - mean_iat)**2 for x in iats) / len(iats)) if len(iats) > 1 else 0
    return mean_iat, std_iat, max_iat, min_iat

def analyze_payloads(packets):
    forward_bytes = sum(len(p['Raw'].load) if p.haslayer('Raw') else 0 for p in packets)
    forward_packets = len(packets)
    return forward_packets, forward_bytes

def extract_features(pcap_path, label="Benign", max_flows=1000, device_name="Unknown"):
    print(f"Extraction started for {device_name} using 120s timeout...")
    if not os.path.exists(pcap_path):
        print(f"File not found: {pcap_path}")
        return []

    flows = defaultdict(list)
    flow_features = []
    
    try:
        reader = PcapReader(pcap_path)
    except Exception as e:
        print(f"Error opening {pcap_path}: {e}")
        return []

    packet_count = 0
    try:
        for packet in reader:
            if not packet.haslayer(IP):
                continue
            
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto
            
            port_src = 0
            port_dst = 0
            if packet.haslayer(TCP):
                port_src = packet[TCP].sport
                port_dst = packet[TCP].dport
            elif packet.haslayer(UDP):
                port_src = packet[UDP].sport
                port_dst = packet[UDP].dport
            else:
                continue

            # Bidirectional flow identifier
            flow_key = tuple(sorted([(ip_src, port_src), (ip_dst, port_dst)])) + (proto,)
            
            # Flow timeout logic
            if flows[flow_key]:
                last_pkt_time = flows[flow_key][-1].time
                current_time = packet.time
                if float(current_time - last_pkt_time) > FLOW_TIMEOUT:
                    # Timeout reached, calculate features for current flow and reset
                    f_pkts = flows[flow_key]
                    if len(f_pkts) > 1:
                        flow_duration = float(f_pkts[-1].time - f_pkts[0].time)
                        if flow_duration > 0:
                            fwd_pkts, fwd_bytes = analyze_payloads(f_pkts)
                            mean_iat, std_iat, max_iat, min_iat = calculate_iat(f_pkts)
                            
                            flow_features.append({
                                'Flow Duration': flow_duration,
                                'Total Fwd Packets': fwd_pkts,
                                'Total Backward Packets': 0,
                                'Total Length of Fwd Packets': fwd_bytes,
                                'Fwd Packet Length Max': max([len(p) for p in f_pkts]),
                                'Fwd Packet Length Min': min([len(p) for p in f_pkts]),
                                'Fwd Packet Length Mean': sum([len(p) for p in f_pkts]) / len(f_pkts),
                                'Flow IAT Mean': mean_iat,
                                'Flow IAT Std': std_iat,
                                'Flow IAT Max': max_iat,
                                'Flow IAT Min': min_iat,
                                'Fwd IAT Total': flow_duration,
                                'Fwd IAT Mean': mean_iat,
                                'Fwd IAT Std': std_iat,
                                'Fwd IAT Max': max_iat,
                                'Fwd IAT Min': min_iat,
                                'Bwd IAT Total': 0,
                                'Bwd IAT Mean': 0,
                                'Bwd IAT Std': 0,
                                'Bwd IAT Max': 0,
                                'Bwd IAT Min': 0,
                                'Fwd PSH Flags': sum(1 for p in f_pkts if p.haslayer(TCP) and p[TCP].flags.P),
                                'Bwd PSH Flags': 0,
                                'Fwd URG Flags': sum(1 for p in f_pkts if p.haslayer(TCP) and p[TCP].flags.U),
                                'Bwd URG Flags': 0,
                                'Fwd Header Length': sum([len(p[IP]) - len(p[IP].payload) for p in f_pkts if hasattr(p[IP], "payload")]),
                                'Bwd Header Length': 0,
                                'Fwd Packets/s': fwd_pkts / flow_duration if flow_duration > 0 else 0,
                                'Bwd Packets/s': 0,
                                'Min Packet Length': min([len(p) for p in f_pkts]),
                                'Max Packet Length': max([len(p) for p in f_pkts]),
                                'Packet Length Mean': sum([len(p) for p in f_pkts]) / len(f_pkts),
                                'Packet Length Std': math.sqrt(sum((len(p) - (sum([len(p) for p in f_pkts]) / len(f_pkts)))**2 for p in f_pkts) / len(f_pkts)) if len(f_pkts) > 1 else 0,
                                'Packet Length Variance': sum((len(p) - (sum([len(p) for p in f_pkts]) / len(f_pkts)))**2 for p in f_pkts) / len(f_pkts) if len(f_pkts) > 1 else 0,
                                'FIN Flag Count': sum(1 for p in f_pkts if p.haslayer(TCP) and p[TCP].flags.F),
                                'SYN Flag Count': sum(1 for p in f_pkts if p.haslayer(TCP) and p[TCP].flags.S),
                                'RST Flag Count': sum(1 for p in f_pkts if p.haslayer(TCP) and p[TCP].flags.R),
                                'PSH Flag Count': sum(1 for p in f_pkts if p.haslayer(TCP) and p[TCP].flags.P),
                                'ACK Flag Count': sum(1 for p in f_pkts if p.haslayer(TCP) and p[TCP].flags.A),
                                'URG Flag Count': sum(1 for p in f_pkts if p.haslayer(TCP) and p[TCP].flags.U),
                                'CWE Flag Count': sum(1 for p in f_pkts if p.haslayer(TCP) and p[TCP].flags.C),
                                'ECE Flag Count': sum(1 for p in f_pkts if p.haslayer(TCP) and p[TCP].flags.E),
                                'Down/Up Ratio': 0,
                                'Average Packet Size': sum([len(p) for p in f_pkts]) / len(f_pkts),
                                'Avg Fwd Segment Size': sum([len(p) for p in f_pkts]) / len(f_pkts),
                                'Avg Bwd Segment Size': 0,
                                'Subflow Fwd Packets': fwd_pkts,
                                'Subflow Fwd Bytes': fwd_bytes,
                                'Init_Win_bytes_forward': f_pkts[0][TCP].window if f_pkts[0].haslayer(TCP) else 0,
                                'Init_Win_bytes_backward': 0,
                                'act_data_pkt_fwd': sum(1 for p in f_pkts if p.haslayer("Raw") and len(p["Raw"].load) > 0),
                                'min_seg_size_forward': min([len(p[IP]) - len(p[IP].payload) for p in f_pkts if hasattr(p[IP], "payload")] + [0]),
                                'Active Mean': 0, 'Active Std': 0, 'Active Max': 0, 'Active Min': 0,
                                'Idle Mean': 0, 'Idle Std': 0, 'Idle Max': 0, 'Idle Min': 0,
                                'Label': label
                            })
                            if len(flow_features) >= max_flows:
                                reader.close()
                                return flow_features
                    
                    flows[flow_key] = []
                    
            flows[flow_key].append(packet)
            
            packet_count += 1
            if packet_count % 50000 == 0:
                print(f"Processed {packet_count} packets...")

    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Error processing packets: {e}")
        
    reader.close()
    return flow_features

all_features = []
os.makedirs("dataset_paper", exist_ok=True)

for dev in devices:
    filepath = os.path.join(PCAP_DIR, dev['filename'])
    features = extract_features(filepath, label="Benign", max_flows=dev['target_flows'], device_name=dev['name'])
    print(f"Extracted {len(features)} flows from {dev['name']}")
    all_features.extend(features)

df = pd.DataFrame(all_features)
df.to_csv(OUTPUT_FILE, index=False)
print(f"Extraction complete! Saved {len(df)} benign flows to {OUTPUT_FILE}")
