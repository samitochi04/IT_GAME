import os

class Config:
    POSTGRES_USER = os.getenv('POSTGRES_USER', 'admin')
    POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD', 'secret')
    POSTGRES_DB = os.getenv('POSTGRES_DB', 'attacks_db')
    POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'db')
    
    SQLALCHEMY_DATABASE_URI = f'postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}/{POSTGRES_DB}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your-secret-key')
    API_RATE_LIMIT = os.getenv('API_RATE_LIMIT', '100/minute')
