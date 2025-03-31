from app import create_app
from app.core.pcap_processor import download_pcap
import threading

app = create_app()

def start_pcap_processor():
    download_pcap()  # Premier téléchargement immédiat
    
if __name__ == "__main__":
    # Démarrer le processus de téléchargement PCAP dans un thread séparé
    pcap_thread = threading.Thread(target=start_pcap_processor)
    pcap_thread.daemon = True
    pcap_thread.start()
    
    # Démarrer l'application Flask
    app.run(host='0.0.0.0', port=5000)
