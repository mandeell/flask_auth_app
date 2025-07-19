from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from zoneinfo import ZoneInfo
import uuid
from cryptography.fernet import Fernet
from config import Config
from sqlalchemy import Index

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=True)  # Allow nullable for OAuth users
    email = db.Column(db.String(120), unique=True, nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    phone_number = db.Column(db.String(20), unique=True, nullable=True)
    profile_picture = db.Column(db.String(255), nullable=True)
    oauth_provider = db.Column(db.String(50))
    oauth_id = db.Column(db.String(120))
    is_oauth = db.Column(db.Boolean, default=False)  # Added OAuth flag
    mfa_secret = db.Column(db.String(255))
    mfa_enabled = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=False)
    token_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    last_activity = db.Column(db.DateTime, default=datetime.now(ZoneInfo('Africa/Lagos')))

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
    created_at = db.Column(db.DateTime, default=datetime.now(ZoneInfo('Africa/Lagos')), nullable=False)

    __table_args__ = (Index('idx_jti', 'jti'),)

class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(ZoneInfo('Africa/Lagos')), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

class RefreshToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(ZoneInfo('Africa/Lagos')), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    __table_args__ = (Index('idx_refresh_jti', 'jti'),)

