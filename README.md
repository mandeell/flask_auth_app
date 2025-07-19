# Flask OAuth Authentication Application

A comprehensive Flask-based authentication system with OAuth integration, multi-factor authentication (MFA), email verification, password reset functionality, and advanced security features.

## 🚀 Features

### Authentication & Authorization
- **User Registration & Login** - Secure user account creation and authentication
- **Google OAuth Integration** - Sign in with Google account
- **JWT Token Management** - Access and refresh token handling with automatic blacklisting
- **Multi-Factor Authentication (MFA)** - TOTP-based two-factor authentication using PyOTP
- **Session Management** - Automatic token cleanup for inactive users

### Security Features
- **Rate Limiting** - Protection against brute force attacks
- **Password Security** - Bcrypt hashing for password storage
- **Email Verification** - Account activation via email confirmation
- **Password Reset** - Secure password recovery via email
- **Token Blacklisting** - Automatic invalidation of compromised tokens
- **HTTPS Enforcement** - Optional HTTPS redirection for production
- **CORS Support** - Cross-origin resource sharing configuration

### User Management
- **Profile Management** - User profile updates with profile picture upload
- **OTP Verification** - One-time password for additional security
- **Activity Tracking** - User activity monitoring with batch processing
- **Account Status** - Active/inactive account management

### Email Features
- **Email Confirmation** - Account verification emails
- **Password Reset Emails** - Secure password recovery
- **Resend Confirmation** - Re-send verification emails
- **Gmail SMTP Integration** - Email delivery via Gmail

## 🛠️ Technology Stack

- **Backend Framework**: Flask 3.1.1
- **Database**: SQLAlchemy with SQLite (configurable)
- **Authentication**: Flask-JWT-Extended, Authlib
- **Email**: Flask-Mail with Gmail SMTP
- **Security**: Flask-Bcrypt, PyOTP, Cryptography
- **Rate Limiting**: Flask-Limiter
- **Task Scheduling**: APScheduler
- **File Uploads**: Flask-Uploads, Pillow
- **CORS**: Flask-CORS

## 📋 Prerequisites

- Python 3.8 or higher
- Gmail account for email functionality
- Google Cloud Console project for OAuth (optional)

## 🔧 Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd flask_oauth_app
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Configuration**
   
   Create a `.env` file in the root directory with the following variables:
   ```env
   # Flask Configuration
   SECRET_KEY=your-secret-key-here
   JWT_SECRET_KEY=your-jwt-secret-key-here
   WTF_CSRF_SECRET_KEY=your-csrf-secret-key-here
   FLASK_ENV=development
   
   # Database Configuration
   SQLALCHEMY_DATABASE_URI=sqlite:///user.db
   
   # Google OAuth Configuration (Optional)
   GOOGLE_CLIENT_ID=your-google-client-id
   GOOGLE_CLIENT_SECRET=your-google-client-secret
   GOOGLE_DISCOVERY_URL=https://accounts.google.com/.well-known/openid-configuration
   SERVER_METADATA_URL=https://accounts.google.com/.well-known/openid-configuration
   
   # Email Configuration
   MAIL_USERNAME=your-gmail-address@gmail.com
   MAIL_PASSWORD=your-gmail-app-password
   
   # Application Configuration
   FERNET_KEY=your-fernet-encryption-key
   BASE_URL=http://127.0.0.1:5000
   
   # Security Configuration (Optional)
   FORCE_HTTPS=false
   ```

5. **Google OAuth Setup (Optional)**
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select existing one
   - Enable Google+ API
   - Create OAuth 2.0 credentials
   - Add authorized redirect URIs: `http://localhost:5000/auth/google/callback`

6. **Gmail App Password Setup**
   - Enable 2-factor authentication on your Gmail account
   - Generate an app-specific password
   - Use this password in the `MAIL_PASSWORD` environment variable

## 🚀 Running the Application

1. **Start the Flask application**
   ```bash
   python app.py
   ```

2. **Access the application**
   - API Base URL: `http://127.0.0.1:5000`
   - The application will create database tables automatically on first run

## 📚 API Endpoints

### Authentication Endpoints

| Method | Endpoint | Description | Rate Limit |
|--------|----------|-------------|------------|
| POST | `/signup` | User registration | Default |
| POST | `/login` | User login | 5/minute |
| POST | `/logout` | User logout | Default |
| POST | `/refresh` | Refresh JWT token | Default |

### OAuth Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/auth/google` | Initiate Google OAuth |
| GET | `/auth/google/callback` | Google OAuth callback |

### Email & Verification

| Method | Endpoint | Description | Rate Limit |
|--------|----------|-------------|------------|
| GET | `/confirm/<token>` | Confirm email address | Default |
| POST | `/resend-confirmation` | Resend confirmation email | 5/minute |
| POST | `/forgot-password` | Request password reset | 5/minute |
| POST | `/reset-password/<token>` | Reset password | 5/minute |

### Multi-Factor Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/mfa` | Setup/verify MFA |
| POST | `/send-otp` | Send OTP code | 5/minute |
| POST | `/verify-otp` | Verify OTP code | 5/minute |

### User Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET/PUT | `/profile` | Get/update user profile |

## 🔒 Security Features

### Rate Limiting
- **Global Limits**: 200 requests/day, 50 requests/hour
- **Endpoint-specific Limits**: 5 requests/minute for sensitive operations
- **Memory-based Storage**: Uses in-memory storage for rate limiting

### Token Management
- **Access Tokens**: 30-minute expiration
- **Refresh Tokens**: 1-day expiration
- **Automatic Blacklisting**: Tokens for inactive users (20+ minutes)
- **Cleanup Jobs**: Scheduled cleanup of expired tokens

### Password Security
- **Bcrypt Hashing**: Industry-standard password hashing
- **Strength Requirements**: Configurable password policies
- **Reset Tokens**: Secure, time-limited password reset tokens

### Data Encryption
- **Fernet Encryption**: MFA secrets encrypted at rest
- **JWT Security**: Secure token generation and validation
- **HTTPS Support**: Optional HTTPS enforcement

## 📁 Project Structure

```
flask_oauth_app/
├── app.py                 # Main application file
├── config.py             # Configuration settings
├── model.py              # Database models
├── requirements.txt      # Python dependencies
├── .env                  # Environment variables (not in repo)
├── .gitignore           # Git ignore rules
├── app.log              # Application logs
├── resources/           # API resource modules
│   ├── __init__.py
│   ├── auth.py          # Login/logout endpoints
│   ├── signup.py        # User registration
│   ├── profile.py       # User profile management
│   ├── mfa.py           # Multi-factor authentication
│   ├── token_refresh.py # Token refresh logic
│   ├── google_auth.py   # Google OAuth integration
│   ├── email_confirmation.py # Email verification
│   ├── password_reset.py # Password reset functionality
│   ├── otp.py           # OTP verification
│   └── utils.py         # Utility functions
├── instance/            # Instance-specific files
├── uploads/             # File upload directory
│   └── profile_pictures/
└── .venv/              # Virtual environment
```

## 🔧 Configuration Options

### Database Configuration
- **SQLite**: Default database (development)
- **PostgreSQL/MySQL**: Supported via SQLAlchemy URI
- **Connection Pooling**: Configurable via SQLAlchemy

### Email Configuration
- **SMTP Server**: Gmail SMTP (configurable)
- **SSL/TLS**: Supports both SSL and TLS
- **Timeout**: Configurable email timeout (default: 20s)

### File Upload Configuration
- **Upload Directory**: `uploads/profile_pictures/`
- **Max File Size**: 16MB
- **Allowed Extensions**: PNG, JPG, JPEG, GIF

## 🔍 Monitoring & Logging

### Application Logging
- **Log Levels**: INFO, WARNING, ERROR
- **Log Destinations**: File (`app.log`) and console
- **Structured Logging**: Timestamp, level, module, message

### Scheduled Tasks
- **Token Cleanup**: Daily cleanup of expired blacklist tokens
- **Inactive User Cleanup**: Every 5 minutes, blacklist tokens for inactive users
- **Activity Batching**: Batch processing of user activity updates

## 🧪 Testing

### Manual Testing
1. **User Registration**: Test signup with email verification
2. **Login Flow**: Test login with and without MFA
3. **OAuth Flow**: Test Google OAuth integration
4. **Password Reset**: Test forgot password functionality
5. **Rate Limiting**: Test rate limit enforcement

### API Testing Tools
- **Postman**: Import API collection for testing
- **curl**: Command-line testing examples
- **HTTPie**: Alternative HTTP client

## 🚀 Deployment

### Production Considerations
1. **Environment Variables**: Set production values in `.env`
2. **Database**: Use PostgreSQL or MySQL for production
3. **HTTPS**: Enable `FORCE_HTTPS=true`
4. **Secret Keys**: Generate secure, random secret keys
5. **Email**: Configure production SMTP settings
6. **Rate Limiting**: Consider Redis for distributed rate limiting

### Docker Deployment (Optional)
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "app.py"]
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Troubleshooting

### Common Issues

1. **Email Not Sending**
   - Verify Gmail app password is correct
   - Check firewall settings for SMTP ports
   - Ensure 2FA is enabled on Gmail account

2. **Google OAuth Not Working**
   - Verify Google Client ID and Secret
   - Check authorized redirect URIs in Google Console
   - Ensure Google+ API is enabled

3. **Database Errors**
   - Check database file permissions
   - Verify SQLAlchemy URI format
   - Ensure database directory exists

4. **Rate Limiting Issues**
   - Check rate limit configuration
   - Consider using Redis for production
   - Monitor rate limit logs

### Debug Mode
Enable debug mode for development:
```python
app.run(debug=True)
```

### Logging
Check `app.log` for detailed error messages and application flow.

## 📞 Support

For support and questions:
- Create an issue in the repository
- Check existing documentation
- Review application logs for error details

---

**Note**: This application is designed for educational and development purposes. For production use, ensure proper security auditing and testing.