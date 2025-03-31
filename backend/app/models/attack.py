from app import db
from datetime import datetime

class Attack(db.Model):
    __tablename__ = 'attacks'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    category = db.Column(db.String(50))
    technique_id = db.Column(db.String(10))
    description = db.Column(db.Text)
    indicators = db.Column(db.JSON)
