import pyshark
import requests
import json
import os
from flask import Flask, jsonify
from datetime import datetime
import threading

# Create Flask app
app = Flask(__name__)

# Store latest results
latest_results = {
    "infected_machine": None,
    "infected_machine_updated": None,
    "submission_result": None,
    "submission_updated": None
}

@app.route('/api/infected-machine', methods=['GET'])
def get_infected_machine():
    """API endpoint to get the latest infected machine information"""
    return jsonify({
        'status': 'success',
        'timestamp': latest_results["infected_machine_updated"],
        'data': latest_results["infected_machine"]
    })

@app.route('/api/submission-result', methods=['GET'])
def get_submission_result():
    """API endpoint to get the latest submission result"""
    return jsonify({
        'status': 'success',
        'timestamp': latest_results["submission_updated"],
        'data': latest_results["submission_result"]
    })

@app.after_request
def add_cors_headers(response):
    """Add CORS headers to allow frontend access"""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

def download_latest_pcap():
    """
    Downloads the latest PCAP file from the API and stores it locally.
    Returns the local file path.
    """
    # Get the filename first
    try:
        filename_response = requests.get("http://93.127.203.48:5000/pcap/latest/filename")
        if filename_response.status_code != 200:
            raise Exception(f"Failed to get filename: {filename_response.status_code}")
        
        filename = filename_response.json().get("filename")
        if not filename:
            raise Exception("No filename received")
        
        # Download the PCAP file
        response = requests.get("http://93.127.203.48:5000/pcap/latest", stream=True)
        if response.status_code != 200:
            raise Exception(f"Failed to download PCAP: {response.status_code}")
        
        # Create pcaps directory if it doesn't exist
        os.makedirs("pcaps", exist_ok=True)
        filepath = os.path.join("pcaps", filename)
        
        # Save the file
        with open(filepath, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        
        print(f"Downloaded PCAP file: {filepath}")
        return filepath
        
    except Exception as e:
        print(f"Error downloading PCAP file: {e}")
        return None

def extract_kerberos_info(pcap_file, filter_str="kerberos.CNameString and kerberos.addr_nb"):
    """
    Extrait les informations Kerberos d'un fichier PCAP : adresse MAC, IP, nom d'hôte, utilisateur Windows.
    """
    unique_results = {}
    capture = pyshark.FileCapture(pcap_file, display_filter=filter_str)

    for packet in capture:
        if hasattr(packet, 'kerberos'):
            kerberos_layer = packet.kerberos
            if hasattr(kerberos_layer, 'CNameString') and hasattr(kerberos_layer, 'addr_nb'):
                if "$" in kerberos_layer.CNameString.lower():
                    continue
                
                ip = packet.ip.src if hasattr(packet, 'ip') else (packet.ipv6.src if hasattr(packet, 'ipv6') else None)
                mac = packet.eth.src if hasattr(packet, 'eth') else None

                if ip and ip not in unique_results:
                    unique_results[ip] = (mac, ip, kerberos_layer.addr_nb, kerberos_layer.CNameString)
    
    capture.close()
    return list(unique_results.values())

def save_to_json(data, filename="results.json"):
    """Enregistre les données dans un fichier JSON sans écraser les anciennes entrées."""
    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as file:
            try:
                existing_data = json.load(file)
            except json.JSONDecodeError:
                existing_data = []
    else:
        existing_data = []

    existing_data.append(data)

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(existing_data, file, indent=4, ensure_ascii=False)

def send_flag(info):
    """Envoie les informations extraites à l'API et enregistre le flag dans un fichier JSON."""
    global latest_results
    
    url = "http://93.127.203.48:5000/pcap/submit"
    
    # Update infected machine info
    machine_info = {
        "mac_address": info[0],
        "ip_address": info[1],
        "hostname": info[2],
        "windows_user": info[3]
    }
    latest_results["infected_machine"] = machine_info
    latest_results["infected_machine_updated"] = datetime.now().isoformat()
    
    data = {
        "user_id": "marchand",
        "lines": [
            info[0],  # MAC address
            info[1],  # IP address
            info[2],  # Host name
            info[3]   # Windows user account
        ]
    }

    try:
        print(f"Envoi des données : {data}")
        response = requests.post(url, json=data)
        response.raise_for_status()
        response_data = response.json()
        print("Réponse de l'API :", response_data)

        # Update submission result
        latest_results["submission_result"] = response_data
        latest_results["submission_updated"] = datetime.now().isoformat()

        # Save to JSON file
        data["flag"] = response_data.get("flag", "Erreur : Flag non reçu")
        save_to_json(data)

    except requests.exceptions.RequestException as e:
        print("Erreur lors de l'envoi de la requête :", e)
        error_data = {"error": str(e)}
        latest_results["submission_result"] = error_data
        latest_results["submission_updated"] = datetime.now().isoformat()
        
        data["flag"] = f"Erreur : {str(e)}"
        save_to_json(data)

def main():
    # Start Flask in a separate thread
    webapp = threading.Thread(target=lambda: app.run(host='0.0.0.0', port=5001, debug=False))
    webapp.daemon = True
    webapp.start()
    
    # Download and analyze PCAP
    pcap_path = download_latest_pcap()
    
    if pcap_path and os.path.exists(pcap_path):
        results = extract_kerberos_info(pcap_path)
        
        if results:
            for info in results:
                send_flag(info)
        else:
            print("Aucune information Kerberos valide trouvée.")
    else:
        print("Failed to download or locate PCAP file.")

if __name__ == "__main__":
    main()