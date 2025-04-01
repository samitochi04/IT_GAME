import requests
from datetime import datetime
import os
from app.core.attack_analyzer import AttackAnalyzer

def download_pcap():
    try:
        url = "http://93.127.203.48:5000/pcap/latest"
        response = requests.get(url)

        if response.status_code == 200:
            # Create a temporary directory if it doesn't exist
            temp_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'temp')
            os.makedirs(temp_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pcap_file = os.path.join(temp_dir, f"capture_{timestamp}.pcap")

            with open(pcap_file, 'wb') as f:
                f.write(response.content)

            analyzer = AttackAnalyzer()
            results = analyzer.analyze_pcap(pcap_file)
            
            # Clean up
            try:
                os.remove(pcap_file)
            except:
                pass
                
            return results
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        }
