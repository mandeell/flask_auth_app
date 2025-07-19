from datetime import datetime
from zoneinfo import ZoneInfo
from flask_restful import Resource
from flask_jwt_extended import (
    jwt_required, get_jwt_identity, get_jwt, 
    create_access_token, create_refresh_token, decode_token
)

from model import User, TokenBlacklist, RefreshToken, db
from .utils import store_refresh_token

class TokenRefreshResources(Resource):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        if not isinstance(current_user, str):
            return {'message': 'Invalid identity type'}, 422
        
        # Get current refresh token info
        current_jti = get_jwt()['jti']
        
        # Find user
        user = User.query.filter_by(token_id=current_user).first()
        if not user:
            return {'message': 'User not found'}, 404
        
        # Update user activity
        user.last_activity = datetime.now(ZoneInfo('Africa/Lagos'))
        
        # Create new tokens
        new_access_token = create_access_token(identity=str(current_user), additional_claims={'username': user.username})
        new_refresh_token = create_refresh_token(identity=str(current_user), additional_claims={'username': user.username})
        
        # Blacklist old refresh token
        db.session.add(TokenBlacklist(jti=current_jti))
        
        # Store new refresh token
        decoded_refresh = decode_token(new_refresh_token)
        expires_at = datetime.fromtimestamp(decoded_refresh['exp'], ZoneInfo('Africa/Lagos'))
        store_refresh_token(user.id, decoded_refresh['jti'], expires_at)
        
        # Mark old refresh token as inactive
        old_refresh = RefreshToken.query.filter_by(jti=current_jti).first()
        if old_refresh:
            old_refresh.is_active = False
        
        db.session.commit()
        
        return {
            'access_token': new_access_token,
            'refresh_token': new_refresh_token
        }, 200