import logging
from flask_restful import Resource
from flask_jwt_extended import create_access_token, create_refresh_token

from model import User, db
from config import Config

logger = logging.getLogger(__name__)

class GoogleLoginResources(Resource):
    def get(self):
        from app import oauth
        google = oauth.create_client('google')
        redirect_url = f'{Config.BASE_URL}/auth/google/callback'
        return google.authorize_redirect(redirect_url)

class GoogleCallbackResources(Resource):
    def get(self):
        try:
            from app import oauth
            google = oauth.create_client('google')
            token = google.authorize_access_token()
            user_info = google.get('https://www.googleapis.com/oauth2/v3/userinfo').json()

            # First, check if user exists by OAuth credentials
            user = User.query.filter_by(oauth_provider='google', oauth_id=user_info['sub']).first()

            if user:
                # User exists with OAuth, proceed with login
                access_token = create_access_token(identity=user.token_id,
                                                   additional_claims={'username': user.username})
                refresh_token = create_refresh_token(identity=user.token_id,
                                                     additional_claims={'username': user.username})
                return {
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                    'message': 'Google Login Successful'
                }, 200

            # Check if user exists with same email (from regular signup)
            existing_user = User.query.filter_by(email=user_info['email']).first()

            if existing_user:
                # Update existing user to link with Google OAuth
                existing_user.oauth_provider = 'google'
                existing_user.oauth_id = user_info['sub']
                # Optionally update name fields if they're empty
                if not existing_user.first_name:
                    existing_user.first_name = user_info.get('given_name')
                if not existing_user.last_name:
                    existing_user.last_name = user_info.get('family_name')

                db.session.commit()

                access_token = create_access_token(identity=existing_user.token_id,
                                                    additional_claims={'username': existing_user.username})
                refresh_token = create_refresh_token(identity=existing_user.token_id,
                                                        additional_claims={'username': existing_user.username})
                return {
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                    'message': 'Google account linked successfully'
                }, 200

            # Create new user if no existing user found
            base_username = user_info['email'].split('@')[0]
            username = base_username
            counter = 1
            while User.query.filter_by(username=username).first():
                username = f'{base_username}{counter}'
                counter += 1

            # Create OAuth user without password (they won't use it for login)
            user = User(
                username=username,
                email=user_info['email'],
                password=None,  # OAuth users don't need passwords
                first_name=user_info.get('given_name'),
                last_name=user_info.get('family_name'),
                oauth_provider='google',
                oauth_id=user_info['sub'],
                is_oauth=True,  # Mark as OAuth user
                is_active=True  # OAuth users are automatically active
            )
            db.session.add(user)
            db.session.commit()

            access_token = create_access_token(identity=user.token_id,
                                                additional_claims={'username': user.username})
            refresh_token = create_refresh_token(identity=user.token_id,
                                                additional_claims={'username': user.username})
            return {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'message': 'Google Login Successful'
            }, 200

        except Exception as e:
            db.session.rollback()
            logger.error(f'Error in Google OAuth Callback: {str(e)}')
            return {'message': 'OAuth authentication failed'}, 500