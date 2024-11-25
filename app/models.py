from datetime import datetime
from app import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    salt = db.Column(db.String(29), nullable=False)
    failed_attempts = db.Column(db.Integer, default=0)
    last_failed_attempt = db.Column(db.DateTime)
    locked_until = db.Column(db.DateTime)
    
class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    challenge_value = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used = db.Column(db.Boolean, default=False)

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    success = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow) 