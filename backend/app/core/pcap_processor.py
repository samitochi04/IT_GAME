import requests
import json
import subprocess
from datetime import datetime
from app import db
from app.models.attack import Attack

def download_pcap():
    try:
        url = "http://93.127.203.48:5000/pcap/latest"
        response = requests.get(url)

        if response.status_code == 200:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pcap_file = f"/tmp/capture_{timestamp}.pcap"

            with open(pcap_file, 'wb') as f:
                f.write(response.content)

            json_file = f"/tmp/capture_{timestamp}.json"
            subprocess.run(['tshark', '-r', pcap_file, '-T', 'json'],
                         stdout=open(json_file, 'w'))

            with open(json_file, 'r') as f:
                data = json.load(f)
                attack = Attack(
                    category='initial_access',
                    technique_id='T1190',
                    description='PCAP Analysis',
                    indicators=data
                )
                db.session.add(attack)
                db.session.commit()
            
            return True
    except Exception as e:
        print(f"Error: {str(e)}")
        return False
