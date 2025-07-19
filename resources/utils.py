import uuid
import random
import os
import logging
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from flask_mail import Message
from flask_restful import reqparse, fields
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer
from email_validator import validate_email as check_email, EmailNotValidError
from werkzeug.utils import secure_filename
from PIL import Image
import io
import base64

from config import Config
from model import RefreshToken, db

# Configure logging
logger = logging.getLogger(__name__)

bcrypt = Bcrypt()

# Import limiter from app - will be set after app initialization
limiter = None

def set_limiter(app_limiter):
    """Set the limiter instance from app.py"""
    global limiter
    limiter = app_limiter

# Initialize URLSafeTimedSerializer for token generation
def get_serializer():
    return URLSafeTimedSerializer(Config.SECRET_KEY)

def validate_email(email):
    try:
        check_email(email)
        logger.info(f'Email address {email} is valid')
        return True
    except EmailNotValidError as e:
        logger.error(f'Email validation for {email}: {str(e)}')
        return False

# Output fields
user_fields = {
    'id': fields.Integer,
    'username': fields.String,
    'email': fields.String,
    'first_name': fields.String,
    'last_name': fields.String,
    'phone_number': fields.String,
    'profile_picture': fields.String,
    'oauth_provider': fields.String,
    'mfa_enabled': fields.Boolean,
}

# Common parsers
signup_parser = reqparse.RequestParser()
signup_parser.add_argument('username', type=str, required=True, help='Username is required')
signup_parser.add_argument('email', type=str, required=True, help='Email is required')
signup_parser.add_argument('password', type=str, required=True, help='Password is required')
signup_parser.add_argument('first_name', type=str)
signup_parser.add_argument('last_name', type=str)
signup_parser.add_argument('phone_number', type=str)
signup_parser.add_argument('profile_picture', type=str)  # Base64 encoded image

login_parser = reqparse.RequestParser()
login_parser.add_argument('username', type=str, required=True, help='Username is required')
login_parser.add_argument('password', type=str, required=True, help='Password is required')
login_parser.add_argument('mfa_code', type=str, location='json')

mfa_parser = reqparse.RequestParser()
mfa_parser.add_argument('mfa_code', type=str, required=True, help='MFA code is required')

forgot_password_parser = reqparse.RequestParser()
forgot_password_parser.add_argument('email', type=str, required=True, help='Email is required')

reset_password_parser = reqparse.RequestParser()
reset_password_parser.add_argument('password', type=str, required=True, help='New password is required')

# OTP parsers
send_otp_parser = reqparse.RequestParser()
send_otp_parser.add_argument('email', type=str, required=True, help='Email is required')

verify_otp_parser = reqparse.RequestParser()
verify_otp_parser.add_argument('email', type=str, required=True, help='Email is required')
verify_otp_parser.add_argument('otp_code', type=str, required=True, help='OTP code is required')
verify_otp_parser.add_argument('username', type=str, required=True, help='Username is required')
verify_otp_parser.add_argument('password', type=str, required=True, help='Password is required')
verify_otp_parser.add_argument('mfa_code', type=str, help='MFA code if enabled')

def send_email(to, subject, template, max_retries=3):
    """Helper function to send emails with retry logic"""
    from app import mail
    msg = Message(
        subject=subject,
        sender=Config.MAIL_DEFAULT_SENDER,
        recipients=[to],
        html=template
    )
    
    for attempt in range(max_retries):
        try:
            logger.info(f'Sending email to {to} (attempt {attempt + 1}/{max_retries})')
            mail.send(msg)
            logger.info('Email sent successfully')
            return True
        except Exception as e:
            logger.error(f'Failed to send email (attempt {attempt + 1}): {str(e)}')
            if attempt == max_retries - 1:
                raise Exception(f"Failed to send email after {max_retries} attempts: {str(e)}")
    return False

def send_email_otp(email, otp_code):
    """Helper function to send OTP via email"""
    try:
        template = f"""
        <html>
        <body>
            <h2>Your Verification Code</h2>
            <p>Your verification code is: <strong>{otp_code}</strong></p>
            <p>This code will expire in 10 minutes.</p>
            <p>If you didn't request this code, please ignore this email.</p>
        </body>
        </html>
        """
        send_email(email, 'Your Verification Code', template)
        return True
    except Exception as e:
        logger.error(f'Failed to send OTP email: {str(e)}')
        return False

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

def validate_image_content(image_data):
    """Validate that the data is actually an image"""
    try:
        # Check if it's a valid image using PIL
        image = Image.open(io.BytesIO(image_data))
        image.verify()  # Verify it's a valid image
        
        # Check image format
        image = Image.open(io.BytesIO(image_data))  # Reopen after verify
        if image.format.lower() not in ['jpeg', 'jpg', 'png', 'gif']:
            return False, "Unsupported image format"
        
        # Check image size (max 5MB)
        if len(image_data) > 5 * 1024 * 1024:
            return False, "Image too large (max 5MB)"
        
        # Check image dimensions (max 2000x2000 pixels)
        if image.width > 2000 or image.height > 2000:
            return False, "Image dimensions too large (max 2000x2000 pixels, 5MB)"
        
        return True, "Valid image"
    except Exception as e:
        return False, f"Invalid image: {str(e)}"

def save_profile_picture(base64_image, user_id):
    """Save base64 encoded profile picture to file system with validation"""
    try:
        # Create upload directory if it doesn't exist
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
        
        # Decode base64 image
        try:
            if ',' in base64_image:
                # Remove data URL prefix if present
                header, base64_data = base64_image.split(',', 1)
                # Validate content type from header
                if 'image/' not in header:
                    logger.error("Invalid content type in base64 header")
                    return None
            else:
                base64_data = base64_image
            
            image_data = base64.b64decode(base64_data)
        except Exception as e:
            logger.error(f"Failed to decode base64 image: {str(e)}")
            return None
        
        # Validate image content
        is_valid, message = validate_image_content(image_data)
        if not is_valid:
            logger.error(f"Image validation failed: {message}")
            return None
        
        # Open and process image
        image = Image.open(io.BytesIO(image_data))
        
        # Convert to RGB if necessary (for PNG with transparency)
        if image.mode in ('RGBA', 'LA', 'P'):
            background = Image.new('RGB', image.size, (255, 255, 255))
            if image.mode == 'P':
                image = image.convert('RGBA')
            background.paste(image, mask=image.split()[-1] if image.mode == 'RGBA' else None)
            image = background
        
        # Resize image to max 500x500 to save space
        image.thumbnail((500, 500), Image.Resampling.LANCZOS)
        
        # Generate unique filename
        filename = f"profile_{user_id}_{uuid.uuid4().hex[:8]}.jpg"
        filepath = os.path.join(Config.UPLOAD_FOLDER, filename)
        
        # Save image
        image.save(filepath, 'JPEG', quality=85, optimize=True)
        
        logger.info(f"Profile picture saved successfully: {filename}")
        return filename
    except Exception as e:
        logger.error(f'Error saving profile picture: {str(e)}')
        return None

def generate_otp():
    """Generate a 6-digit OTP"""
    return str(random.randint(100000, 999999))

def store_refresh_token(user_id, jti, expires_at):
    """Store refresh token in database"""
    refresh_token = RefreshToken(
        jti=jti,
        user_id=user_id,
        expires_at=expires_at
    )
    db.session.add(refresh_token)
    db.session.commit()

def rate_limit(limit_string):
    def decorator(method):
        if limiter is None:
            raise RuntimeError('Limiter not initialized')
        return limiter.limit(limit_string)(method)
    return decorator