from flask_sqlalchemy import SQLAlchemy
import datetime
import uuid
from cryptography.fernet import Fernet
from config import Config
from sqlalchemy import Index

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    oauth_provider = db.Column(db.String(50))
    oauth_id = db.Column(db.String(120))
    mfa_secret = db.Column(db.String(255))
    mfa_enabled = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=False)
    token_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))

    def set_mfa_secret(self, secret):
        f = Fernet(Config.FERNET_KEY)
        self.mfa_secret = f.encrypt(secret.encode()).decode()

    def get_mfa_secret(self):
        if self.mfa_secret:
            f = Fernet(Config.FERNET_KEY)
            return f.decrypt(self.mfa_secret.encode()).decode()
        return None

class TokenBlacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)

    __table_args__ = (Index('idx_jti', 'jti'),)