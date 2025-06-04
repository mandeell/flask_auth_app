import datetime
from flask import Flask
from flask_mail import Mail
from flask_restful import Api
from flask_jwt_extended import JWTManager
from authlib.integrations.flask_client import OAuth
from model import db, TokenBlacklist
from resources import (
    SignupResources, LoginResources, MFASetupResources,
    TokenRefreshResources, LogoutResources, ProfileResources,
    GoogleLoginResources, GoogleCallbackResources)
from config import Config
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
api = Api(app)
jwt = JWTManager(app)
oauth = OAuth(app)
mail = Mail(app)


# Configure Google Oauth
print("Google Client Id:", app.config['GOOGLE_CLIENT_ID'])
print("Google Client Secret:", app.config['GOOGLE_CLIENT_SECRET'])
print("Google Discovery URL:", app.config['GOOGLE_DISCOVERY_URL'])
oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

# JWT Callbacks for Debugging
@jwt.invalid_token_loader
def invalid_token_callback(error):
    print("Invalid Token Error:", str(error))
    return {'message': 'Invalid or expired token', 'error': str(error)}, 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    print("Unauthorized Error:", str(error))
    return {'message': 'Missing authorization token'}, 401

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    print("Checking Token JTI:", jti)
    token = db.session.query(TokenBlacklist).filter_by(jti=jti).first()
    return token is not None

@jwt.token_verification_failed_loader
def token_verification_failed_callback(jwt_header, jwt_payload):
    print("JWT Header:", jwt_header)
    print("JWT Payload:", jwt_payload)
    print("Sub Claim:", jwt_payload.get('sub'))
    return {'message': 'Token verification failed'}, 401

# Token database tables
with app.app_context():
    db.create_all()

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

print("Server Time (UTC):", datetime.datetime.now(datetime.UTC))
print("Server Time (local):", datetime.datetime.now())
if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc')