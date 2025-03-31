FROM python:3.9

WORKDIR /app

# Installation de tshark
RUN apt-get update && \
    apt-get install -y tshark && \
    rm -rf /var/lib/apt/lists/*

# Installation des dépendances Python
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copie du code source
COPY . /app

# Ajouter le répertoire au PYTHONPATH
ENV PYTHONPATH=/app

# Exposer le port
EXPOSE 5000

# Commande de démarrage
CMD ["python", "main.py"]