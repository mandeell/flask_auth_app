import os
from dotenv import load_dotenv
from datetime import timedelta
from cryptography.fernet import Fernet
import logging

load_dotenv()
logger = logging.getLogger(__name__)

def get_or_generate_fernet_key():
    """Get FERNET_KEY from environment or generate a new one"""
    key = os.environ.get('FERNET_KEY')
    if not key and os.environ.get('FLASK_ENV') == 'development':
        key = Fernet.generate_key().decode()
        logger.warning(f"FERNET_KEY not set. Generated: {key}. Add to .env to avoid data loss.")
    return key

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///user.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=1)
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']
    JWT_TOKEN_LOCATION = ['headers']
    # JWT_COOKIE_SECURE will be set dynamically in app.py based on request context
    JWT_COOKIE_SECURE = False  # Default value, will be overridden
    JWT_COOKIE_CSRF_PROTECT = True
    JWT_IDENTITY_CLAIM = 'sub'
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
    GOOGLE_DISCOVERY_URL = os.environ.get('GOOGLE_DISCOVERY_URL')
    FERNET_KEY = get_or_generate_fernet_key()
    BASE_URL = os.environ.get('BASE_URL')
    SERVER_METADATA_URL=os.environ.get('SERVER_METADATA_URL')
    
    # HTTPS enforcement
    FORCE_HTTPS = os.environ.get('FORCE_HTTPS', 'false').lower() == 'true'

    MAIL_SERVER = 'smtp.gmail.com'
    # MAIL_PORT = 587
    # MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_USERNAME')
    MAIL_TIMEOUT = 20  # Increase timeout to 20 seconds
    MAIL_DEBUG = True  # Enable debugging
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    MAIL_USE_TLS = False
    
    # File Upload Configuration
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads', 'profile_pictures')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}