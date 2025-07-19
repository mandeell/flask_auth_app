from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from flask import Flask, request, redirect, url_for
from flask_mail import Mail
from flask_restful import Api
from flask_jwt_extended import JWTManager
from authlib.integrations.flask_client import OAuth
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from model import db, TokenBlacklist, User, RefreshToken, OTP
from resources import (
    SignupResources, LoginResources, MFASetupResources,
    TokenRefreshResources, LogoutResources, ProfileResources,
    GoogleLoginResources, GoogleCallbackResources, ConfirmEmailResource,
    ForgotPasswordResource, ResetPasswordResource, ResendConfirmationResource,
    SendOTPResource, VerifyOTPResource, set_limiter
)
from config import Config
from dotenv import load_dotenv
from flask_cors import CORS
import logging
import os
from apscheduler.schedulers.background import BackgroundScheduler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

load_dotenv()
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
app.config.from_object(Config)

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Set limiter for resources
set_limiter(limiter)

# Apply rate limiting to resource methods
LoginResources.post = limiter.limit("5 per minute")(LoginResources.post)
ForgotPasswordResource.post = limiter.limit("5 per minute")(ForgotPasswordResource.post)
ResetPasswordResource.post = limiter.limit("5 per minute")(ResetPasswordResource.post)
ResendConfirmationResource.post = limiter.limit("5 per minute")(ResendConfirmationResource.post)
SendOTPResource.post = limiter.limit("5 per minute")(SendOTPResource.post)
VerifyOTPResource.post = limiter.limit("5 per minute")(VerifyOTPResource.post)

# Enable sessions
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Initialize extensions
db.init_app(app)
api = Api(app)
jwt = JWTManager(app)
oauth = OAuth(app)
mail = Mail(app)


# Configure Google Oauth
oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url=app.config['SERVER_METADATA_URL'],
    client_kwargs={'scope': 'openid email profile'},
)

def cleanup_blacklist():
    with app.app_context():
        try:
            expiration = datetime.now(ZoneInfo('Africa/Lagos')) - timedelta(days=30)
            deleted_count = TokenBlacklist.query.filter(TokenBlacklist.created_at < expiration).delete()
            db.session.commit()
            logger.info(f"Cleaned up {deleted_count} expired blacklist tokens")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error during cleanup_blacklist: {str(e)}")

def cleanup_inactive_tokens():
    """Blacklist tokens for users inactive for more than 20 minutes"""
    with app.app_context():
        try:
            from flask_jwt_extended import get_jwt_identity, get_jwt
            cutoff_time = datetime.now(ZoneInfo('Africa/Lagos')) - timedelta(minutes=20)

            # Find users who have been inactive for more than 20 minutes
            inactive_users = User.query.filter(User.last_activity < cutoff_time).all()
            blacklisted_count = 0
    
            for user in inactive_users:
                # Find all active refresh tokens for this user
                active_refresh_tokens = RefreshToken.query.filter_by(
                    user_id=user.id,
                    is_active=True
                ).all()

                for token in active_refresh_tokens:
                    # Add to blacklist
                    blacklist_entry = TokenBlacklist(jti=token.jti)
                    db.session.add(blacklist_entry)
                    # Mark refresh token as inactive
                    token.is_active = False
                    blacklisted_count += 1
            db.session.commit()
            logger.info(f"Blacklisted {blacklisted_count} tokens for inactive users")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error during cleanup_inactive_tokens: {str(e)}")

# HTTPS enforcement middleware and JWT cookie security
@app.before_request
def force_https():
    if Config.FORCE_HTTPS and not request.is_secure and request.headers.get('X-Forwarded-Proto') != 'https':
        return redirect(request.url.replace('http://', 'https://'), code=301)
    
    # Set JWT_COOKIE_SECURE dynamically based on request
    app.config['JWT_COOKIE_SECURE'] = request.is_secure or os.environ.get('FORCE_HTTPS') == 'true'

# Middleware to track user activity with batching for scalability
user_activity_batch = []
BATCH_SIZE = 10

@app.before_request
def track_user_activity():
    from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
    from flask import request
    
    # Skip tracking for certain endpoints
    skip_endpoints = ['/login', '/signup', '/auth/google', '/auth/google/callback', 
                     '/confirm', '/forgot-password', '/reset-password', '/resend-confirmation']
    
    if any(request.path.startswith(endpoint) for endpoint in skip_endpoints):
        return
    
    try:
        verify_jwt_in_request(optional=True)
        user_token_id = get_jwt_identity()
        if user_token_id:
            # Add to batch instead of immediate database write
            user_activity_batch.append({
                'token_id': user_token_id,
                'timestamp': datetime.now(ZoneInfo('Africa/Lagos'))
            })
            
            # Process batch when it reaches the limit
            if len(user_activity_batch) >= BATCH_SIZE:
                process_activity_batch()
    except Exception as e:
        logger.error(f"Error tracking user activity: {str(e)}")

def process_activity_batch():
    """Process batched user activity updates"""
    global user_activity_batch
    if not user_activity_batch:
        return

    with app.app_context():
        try:
            # Group by token_id and get latest timestamp
            activity_map = {}
            for activity in user_activity_batch:
                token_id = activity['token_id']
                timestamp = activity['timestamp']
                if token_id not in activity_map or timestamp > activity_map[token_id]:
                    activity_map[token_id] = timestamp

            # Update database in batch
            for token_id, timestamp in activity_map.items():
                user = User.query.filter_by(token_id=token_id).first()
                if user:
                    user.last_activity = timestamp

            db.session.commit()
            user_activity_batch.clear()
            logger.info(f"Processed activity batch for {len(activity_map)} users")

        except Exception as e:
            logger.error(f"Error processing activity batch: {str(e)}")
            db.session.rollback()
            user_activity_batch.clear()

# Error handlers
@app.errorhandler(404)
def not_found(error):
    logger.warning(f"404 error: {request.url}")
    return {'message': 'Resource not found'}, 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 error: {str(error)}")
    db.session.rollback()
    return {'message': 'Internal server error'}, 500

@app.errorhandler(429)
def ratelimit_handler(e):
    logger.warning(f"Rate limit exceeded: {request.remote_addr}")
    return {'message': 'Rate limit exceeded', 'retry_after': str(e.retry_after)}, 429

# JWT Callbacks for Debugging
@jwt.invalid_token_loader
def invalid_token_callback(error):
    return {'message': 'Invalid or expired token', 'error': str(error)}, 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return {'message': 'Missing authorization token'}, 401

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    with app.app_context():
        jti = jwt_payload['jti']
        token = db.session.query(TokenBlacklist).filter_by(jti=jti).first()
        return token is not None

@jwt.token_verification_failed_loader
def token_verification_failed_callback(jwt_header, jwt_payload):
    return {'message': 'Token verification failed'}, 401

# Create database tables
with app.app_context():
    db.create_all()
    scheduler = BackgroundScheduler()
    if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        scheduler.add_job(func=cleanup_blacklist, trigger="interval", days=1, id='cleanup_blacklist')
        scheduler.add_job(func=cleanup_inactive_tokens, trigger="interval", minutes=5, id='cleanup_inactive_tokens')
        scheduler.start()
        logger.info("APScheduler started with cleanup jobs")

# Add resources
api.add_resource(SignupResources, '/signup')
api.add_resource(LoginResources, '/login')
api.add_resource(MFASetupResources, '/mfa')
api.add_resource(TokenRefreshResources, '/refresh')
api.add_resource(LogoutResources, '/logout')
api.add_resource(ProfileResources, '/profile')
api.add_resource(GoogleLoginResources, '/auth/google')
api.add_resource(GoogleCallbackResources, '/auth/google/callback')
api.add_resource(ConfirmEmailResource, '/confirm/<token>')
api.add_resource(ForgotPasswordResource, '/forgot-password')
api.add_resource(ResetPasswordResource, '/reset-password/<token>')
api.add_resource(ResendConfirmationResource, '/resend-confirmation')
api.add_resource(SendOTPResource, '/send-otp')
api.add_resource(VerifyOTPResource, '/verify-otp')


if __name__ == '__main__':
    app.run(debug=True)