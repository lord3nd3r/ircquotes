# ircquotes Production Deployment

## Configuration Management

### Configuration File: `config.json`
All application settings are now centralized in `config.json`. You can easily modify:

- **App settings** (host, port, debug mode)
- **Database configuration** (URI, connection pool settings)
- **Security settings** (CSRF, session cookies, security headers)
- **Rate limiting** (per-endpoint limits)
- **Quote settings** (length limits, pagination)
- **Admin credentials**
- **Feature toggles**

### Viewing Current Configuration
```bash
python config_manager.py
```

### Updating Configuration
```bash
# Change port
python config_manager.py app.port 8080

# Change quotes per page
python config_manager.py quotes.per_page 50

# Disable CSRF (not recommended)
python config_manager.py security.csrf_enabled false

# Change rate limits
python config_manager.py rate_limiting.endpoints.login "10 per minute"
```

## Running with Gunicorn (Production)

### Quick Start
```bash
# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run with Gunicorn (recommended for production)
gunicorn --config gunicorn.conf.py app:app
```

### Alternative Gunicorn Commands

**Basic production run:**
```bash
gunicorn -w 4 -b 0.0.0.0:5050 app:app
```

**With more workers (for higher traffic):**
```bash
gunicorn -w 8 -b 0.0.0.0:5050 --timeout 30 app:app
```

**Behind a reverse proxy (nginx/apache):**
```bash
gunicorn -w 4 -b 127.0.0.1:5050 app:app
```

### Environment Variables for Production
```bash
export FLASK_ENV=production
```

## Security Notes

- All major security vulnerabilities have been fixed
- CSRF protection enabled
- XSS protection with output escaping
- SQL injection prevention
- Rate limiting on all endpoints
- Secure session configuration
- Security headers added

## Admin Access
- Username: Configurable in `config.json` (default: admin)
- Password: Use the Argon2 hashed password in `config.json`

## Configuration Examples

### High-Traffic Setup
```json
{
  "quotes": {
    "per_page": 50
  },
  "rate_limiting": {
    "endpoints": {
      "vote": "120 per minute",
      "search": "60 per minute"
    }
  }
}
```

### Development Setup
```json
{
  "app": {
    "debug": true,
    "port": 5000
  },
  "security": {
    "session_cookie_secure": false
  },
  "logging": {
    "level": "DEBUG"
  }
}
```

### Production Security Setup
```json
{
  "security": {
    "session_cookie_secure": true,
    "csrf_enabled": true
  },
  "logging": {
    "level": "WARNING"
  }
}
```