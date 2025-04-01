# Architecture de Détection d'Attaques - MITRE ATT&CK

## Architecture Globale

```
├── Docker
│   ├── backend (Python Flask + tshark)
│   └── frontend (Angular)
├── API REST
│   ├── GET /api/attacks/latest
│   ├── GET /api/attacks/history
│   └── GET /api/attacks/categories/{category}
└── Base de données (PostgreSQL)
```
## Analyse des logs
Analysez les fichiers PCAP de façon automatisée. 
Détectez et catégorisez les attaques selon le référentiel MITRE ATT&CK, en modélisant 
clairement les étapes : 
• Initial access 
• Execution 
• Persistence 
• Privilege escalation 
• Defense evasion 
• Credential access 
• Discovery 
• Lateral movement 
• Collection

## Prérequis

- Python 3.x
- pip (gestionnaire de paquets Python)
- tshark (outil de ligne de commande Wireshark)

## Installation avec Docker

### Structure des Dossiers

```
.
├── docker-compose.yml   # Main docker-compose file 
├── backend/
│   ├── Dockerfile  # Backend Dockerfile
│   ├── requirements.txt
│   ├── app/
│       ├── __init__.py
│       ├── pcap_processor.py
│       ├── attack_analyzer.py
│       └── api.py
│   
└── frontend/
    ├── Dockerfile      # Frontend Dockerfile
    └── [Angular files]
```

### Configuration Docker

```yaml
# docker-compose.yml
version: "3.8"
services:
  db:
    image: postgres:latest
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_DB=attacks_db
      - POSTGRES_USER=admin
      - POSTGRES_PASSWORD=secret
    volumes:
      - postgres_data:/var/lib/postgresql/data

  backend:
    build: ./backend
    ports:
      - "5000:5000"
    depends_on:
      - db
    environment:
      - DATABASE_URL=postgresql://admin:secret@db:5432/attacks_db

  frontend:
    build: ./frontend
    ports:
      - "4200:4200"
    depends_on:
      - backend

volumes:
  postgres_data:
```

## Installation des dépendances

```bash
pip install requests
pip install schedule
```

## Installation de tshark

### Sur Windows

1. Télécharger et installer Wireshark depuis https://www.wireshark.org/
2. Ajouter le chemin de tshark aux variables d'environnement (généralement `C:\Program Files\Wireshark`)

## Script Python

Créez un fichier `pcap_processor.py` avec le code suivant :

```python
import requests
import json
import subprocess
import schedule
import time
from datetime import datetime

def download_pcap():
    url = "http://93.127.203.48:5000/pcap/latest"
    response = requests.get(url)

    if response.status_code == 200:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_file = f"capture_{timestamp}.pcap"

        # Sauvegarder le fichier PCAP
        with open(pcap_file, 'wb') as f:
            f.write(response.content)

        # Convertir PCAP en JSON
        json_file = f"capture_{timestamp}.json"
        subprocess.run(['tshark', '-r', pcap_file, '-T', 'json'],
                      stdout=open(json_file, 'w'))

        # Traiter le fichier JSON
        process_json(json_file)

def process_json(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)
        # Ajoutez ici votre logique de traitement
        print(f"Traitement du fichier {json_file}")

# Planifier l'exécution quotidienne
schedule.every().day.at("00:00").do(download_pcap)

if __name__ == "__main__":
    while True:
        schedule.run_pending()
        time.sleep(60)
```

## Traitement des Attaques MITRE ATT&CK

### Catégorisation des Attaques

Le système analyse les fichiers PCAP selon les tactiques MITRE ATT&CK :

1. **Initial Access**

   - Détection des tentatives d'accès externes
   - Analyse des ports ouverts suspects
   - Identification des malwares

2. **Execution**

   - Détection des charges utiles malveillantes
   - Analyse des scripts suspects
   - Identification des processus anormaux

3. **Persistence**

   - Détection des backdoors
   - Analyse des modifications de registre
   - Surveillance des tâches planifiées

4. **Privilege Escalation**

   - Détection des élévations de privilèges
   - Analyse des exploits
   - Surveillance des modifications de permissions

5. **Defense Evasion**

   - Détection des tentatives de contournement
   - Analyse du trafic chiffré suspect
   - Identification des techniques d'obfuscation

6. **Credential Access**

   - Détection des tentatives de vol d'identifiants
   - Analyse du trafic LDAP/Kerberos
   - Surveillance des authentifications

7. **Discovery**

   - Détection des scans de réseau
   - Analyse des requêtes DNS
   - Identification des énumérations de système

8. **Lateral Movement**

   - Détection des mouvements entre systèmes
   - Analyse du trafic SMB/RDP
   - Surveillance des connexions internes

9. **Collection**
   - Détection des exfiltrations de données
   - Analyse des transferts de fichiers
   - Surveillance des copies de données

## API REST

### Endpoints

```
GET /api/attacks/latest
- Retourne les dernières attaques détectées
- Format: JSON
- Paramètres: ?category=initial_access

GET /api/attacks/history
- Retourne l'historique des attaques
- Format: JSON
- Paramètres: ?start_date=2023-01-01&end_date=2023-12-31

GET /api/attacks/categories/{category}
- Retourne les attaques par catégorie
- Format: JSON
- Categories: initial_access, execution, persistence, etc.
```

### Format de Réponse

```json
{
  "attacks": [
    {
      "id": "1",
      "timestamp": "2023-12-01T12:00:00Z",
      "category": "initial_access",
      "technique": "T1190",
      "description": "Exploit Public-Facing Application",
      "severity": "high",
      "indicators": ["192.168.1.1", "POST /admin", "..."],
      "mitigations": ["Update application", "Enable WAF"]
    }
  ],
  "metadata": {
    "total": 100,
    "page": 1,
    "per_page": 10
  }
}
```

## Utilisation

1. Assurez-vous que toutes les dépendances sont installées
2. Exécutez le script :

```bash
python pcap_processor.py
```

Le script va :

1. Se connecter à l'API et télécharger le dernier fichier PCAP
2. Convertir le fichier PCAP en JSON using tshark
3. Traiter le fichier JSON selon vos besoins
4. S'exécuter automatiquement chaque jour à minuit

## Déploiement

1. Cloner le repository

```bash
git clone [repository-url]
```

2. Construire et démarrer les conteneurs

```bash
docker-compose up --build
```

3. Vérifier les services

```bash
docker-compose ps
```

4. Accéder aux applications

- Frontend: http://localhost:4200
- Backend API: http://localhost:5000
- PostgreSQL: postgresql://localhost:5432

## Surveillance et Maintenance

### Logs Docker

```bash
docker-compose logs -f [service-name]
```

### Backup PostgreSQL

```bash
docker exec db pg_dump -U admin attacks_db > backup.sql
```

### Restore PostgreSQL

```bash
cat backup.sql | docker exec -i db psql -U admin attacks_db
```

### Mise à jour des conteneurs

```bash
docker-compose pull
docker-compose up -d
```

## Personnalisation

Vous pouvez modifier :

- L'heure d'exécution dans `schedule.every().day.at("00:00")`
- La logique de traitement dans la fonction `process_json()`

## Développement

Pour le développement local sans Docker :

- Installez les dépendances Python
- Configurez PostgreSQL localement
- Exécutez les scripts Python directement
