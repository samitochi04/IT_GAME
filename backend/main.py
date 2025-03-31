import os
import sys
from flask import Flask, jsonify, Response
from flask_cors import CORS
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.pcap_processor import download_pcap
from app.core.attack_analyzer import AttackAnalyzer

app = Flask(__name__)
CORS(app)

@app.route('/api/analyze/latest', methods=['GET'])
def analyze_latest():
    try:
        results = download_pcap()
        response = {
            'success': True,
            'data': {
                'analysis': results,
                'timestamp': results.get('timestamp', ''),
                'summary': {
                    'status': results.get('status', 'unknown'),
                    'total_packets': results.get('statistics', {}).get('total_packets', 0),
                    'suspicious_packets': results.get('statistics', {}).get('suspicious_packets', 0),
                }
            }
        }
        return jsonify(response), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({
        'status': 'online',
        'version': '1.0'
    })

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
