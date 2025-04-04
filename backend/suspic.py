from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, Raw
from collections import defaultdict
from flask import Flask, jsonify
import threading
import json
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)

# Global storage for results
latest_results = {
    "suspicious_ips": [],
    "last_updated": None
}

def analyze_pcap(pcap_file):
    """Analyze PCAP file and detect suspicious IPs"""
    packets = rdpcap(pcap_file)
    
    # Counters for detection
    ip_counter = defaultdict(int)
    port_counter = defaultdict(int)
    icmp_counter = defaultdict(int)
    brute_force_attempts = defaultdict(int)
    suspicious_ips = []
    
    # Analyze packets
    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ip_counter[src_ip] += 1
            
            if packet.haslayer(ICMP):
                icmp_counter[src_ip] += 1
            
            if packet.haslayer(TCP) or packet.haslayer(UDP):
                src_port = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport
                dst_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
                
                if dst_port in [22, 23, 3389, 80, 443]:
                    port_counter[(src_ip, dst_port)] += 1
                    if port_counter[(src_ip, dst_port)] > 5:
                        brute_force_attempts[src_ip] += 1
    
    # Detect suspicious behavior
    for ip, count in ip_counter.items():
        if count > 100:
            suspicious_ips.append({"ip": ip, "reason": "High packet volume", "count": count})
    
    for ip, count in icmp_counter.items():
        if count > 50:
            suspicious_ips.append({"ip": ip, "reason": "High ICMP traffic", "count": count})
    
    for (ip, port), count in port_counter.items():
        if count > 10:
            suspicious_ips.append({"ip": ip, "reason": f"Port scan on {port}", "count": count})
    
    for ip, attempts in brute_force_attempts.items():
        if attempts > 3:
            suspicious_ips.append({"ip": ip, "reason": "Potential brute force attempt", "count": attempts})
    
    return suspicious_ips

@app.route('/api/suspicious-ips', methods=['GET'])
def get_suspicious_ips():
    """API endpoint to get suspicious IPs"""
    return jsonify({
        'status': 'success',
        'timestamp': latest_results["last_updated"],
        'data': latest_results["suspicious_ips"]
    })

@app.after_request
def add_cors_headers(response):
    """Add CORS headers to allow frontend access"""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

def download_latest_pcap():
    """Download the latest PCAP file from the API"""
    try:
        # Get the filename first
        filename_response = requests.get("http://93.127.203.48:5000/pcap/latest/filename")
        if filename_response.status_code != 200:
            raise Exception(f"Failed to get filename: {filename_response.status_code}")
        
        filename = filename_response.json().get("filename")
        if not filename:
            raise Exception("No filename received")
        
        # Download PCAP
        response = requests.get("http://93.127.203.48:5000/pcap/latest", stream=True)
        if response.status_code != 200:
            raise Exception(f"Failed to download PCAP: {response.status_code}")
        
        return filename, response.content
    except Exception as e:
        print(f"Error downloading PCAP: {e}")
        return None, None

def main():
    # Start Flask in a separate thread
    webapp = threading.Thread(target=lambda: app.run(host='0.0.0.0', port=5002, debug=False))
    webapp.daemon = True
    webapp.start()
    
    last_filename = None
    check_interval = 300  # Check every 5 minutes
    
    while True:
        try:
            # Get latest PCAP
            filename, pcap_content = download_latest_pcap()
            
            if filename and filename != last_filename:
                print(f"New PCAP file detected: {filename}")
                
                # Save PCAP content to temporary file
                with open(filename, 'wb') as f:
                    f.write(pcap_content)
                
                # Analyze PCAP file
                suspicious_ips = analyze_pcap(filename)
                
                # Update global results
                latest_results["suspicious_ips"] = suspicious_ips
                latest_results["last_updated"] = datetime.now().isoformat()
                
                print(f"Analysis complete. Found {len(suspicious_ips)} suspicious IPs.")
                print("API endpoint available at: http://localhost:5002/api/suspicious-ips")
                
                last_filename = filename
            else:
                print("No new PCAP file detected.")
            
            # Wait before next check
            print(f"Waiting {check_interval} seconds before next check...")
            time.sleep(check_interval)
            
        except Exception as e:
            print(f"Error in main loop: {e}")
            time.sleep(60)  # Wait 1 minute on error

if __name__ == "__main__":
    import requests
    import time
    main()