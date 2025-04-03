from flask import Flask, jsonify
import pyshark
import requests
import tempfile
from datetime import datetime
import os
import asyncio
import nest_asyncio

app = Flask(__name__)

def download_pcap():
    """Download the latest PCAP file from the API"""
    url = "http://93.127.203.48:5000/pcap/latest"
    response = requests.get(url)
    if response.status_code == 200:
        return response.content
    raise Exception("Failed to download PCAP file")

def analyze_pcap(pcap_content):
    """Analyze PCAP file and extract relevant information"""
    packets_data = []
    temp_path = None
    capture = None
    
    try:
        # Create temp file with delete=True to ensure cleanup
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            temp_path = tmp_file.name
            tmp_file.write(pcap_content)
            tmp_file.flush()
        
        # Set up event loop for async operations
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        nest_asyncio.apply()
        
        # Open and analyze the PCAP file
        capture = pyshark.FileCapture(temp_path, eventloop=loop)
        
        for packet in capture:
            if hasattr(packet, 'ip'):
                packet_info = {
                    'source_ip': packet.ip.src,
                    'destination_ip': packet.ip.dst,
                    'protocol': packet.highest_layer,
                    'info': get_packet_info(packet),
                    'timestamp': datetime.fromtimestamp(float(packet.sniff_timestamp)).isoformat()
                }
                packets_data.append(packet_info)
    
    except Exception as e:
        raise Exception(f"Error analyzing PCAP: {str(e)}")
    
    finally:
        # Ensure proper cleanup of resources
        if capture:
            capture.close()
            
        # Clean up the event loop
        try:
            loop = asyncio.get_event_loop()
            loop.stop()
            loop.close()
        except:
            pass
        
        # Close FileCapture and wait a bit before deleting
        if temp_path and os.path.exists(temp_path):
            try:
                import time
                time.sleep(0.1)  # Small delay to ensure file handles are released
                os.unlink(temp_path)
            except Exception as e:
                print(f"Warning: Could not delete temporary file {temp_path}: {e}")
    
    return packets_data

def get_packet_info(packet):
    """Extract detailed information from packet based on protocol"""
    info = ""
    
    try:
        if hasattr(packet, 'http'):
            if hasattr(packet.http, 'request_method'):
                info = f"HTTP {packet.http.request_method} {packet.http.request_uri}"
            elif hasattr(packet.http, 'response_code'):
                info = f"HTTP Response {packet.http.response_code}"
        elif hasattr(packet, 'dns'):
            if hasattr(packet.dns, 'qry_name'):
                info = f"DNS Query: {packet.dns.qry_name}"
        elif hasattr(packet, 'tcp'):
            info = f"TCP {packet.tcp.srcport} → {packet.tcp.dstport}"
        elif hasattr(packet, 'udp'):
            info = f"UDP {packet.udp.srcport} → {packet.udp.dstport}"
    except Exception as e:
        info = "Unable to extract info"
    
    return info

@app.route('/api/pcap/analyze', methods=['GET'])
def get_pcap_analysis():
    """API endpoint to get PCAP analysis"""
    try:
        # Download PCAP file
        pcap_content = download_pcap()
        
        # Analyze PCAP
        packets_data = analyze_pcap(pcap_content)
        
        return jsonify({
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'packet_count': len(packets_data),
            'packets': packets_data
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.after_request
def add_cors_headers(response):
    """Add CORS headers to allow frontend access"""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
