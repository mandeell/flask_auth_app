from datetime import datetime, timedelta
from flask import Flask
from flask_mail import Mail
from flask_restful import Api
from flask_jwt_extended import JWTManager
from authlib.integrations.flask_client import OAuth
from model import db, TokenBlacklist
from resources import (
    SignupResources, LoginResources, MFASetupResources,
    TokenRefreshResources, LogoutResources, ProfileResources,
    GoogleLoginResources, GoogleCallbackResources, ConfirmEmailResource,
    ForgotPasswordResource, ResetPasswordResource, ResendConfirmationResource
)
from config import Config
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.config.from_object(Config)

# Enable sessions
app.config['SESSION_COOKIE_SECURE'] = True  # Use HTTPS
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
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

def cleanup_blacklist():
    expiration = datetime.utcnow() - timedelta(days=30)
    TokenBlacklist.query.filter(TokenBlacklist.created_at < expiration).delete()
    db.session.commit()

# JWT Callbacks for Debugging
@jwt.invalid_token_loader
def invalid_token_callback(error):

    return {'message': 'Invalid or expired token', 'error': str(error)}, 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return {'message': 'Missing authorization token'}, 401

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    token = db.session.query(TokenBlacklist).filter_by(jti=jti).first()
    return token is not None

@jwt.token_verification_failed_loader
def token_verification_failed_callback(jwt_header, jwt_payload):
    return {'message': 'Token verification failed'}, 401

# Create database tables
with app.app_context():
    db.create_all()
    from apscheduler.schedulers.background import BackgroundScheduler
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=cleanup_blacklist, trigger="interval", days=1)
    scheduler.start()

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


if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc')