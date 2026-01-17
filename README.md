# ircquotes

A modern, robust quote archive application built with Flask. Designed originally for archiving IRC (Internet Relay Chat) logs, it serves as a general-purpose text quote repository with community submission, voting, and moderation features.

## Features

- **Quote Management**
  - Public submission interface with preview functionality.
  - IP-based rate limiting to prevent spam (60-second cooldown).
  - Legacy date support and automatic timestamping for new submissions.
  - "Copy to Clipboard" functionality for easy sharing.

- **Moderation System**
  - Secure Admin Panel (`/modapp`) protected by Argon2 authentication.
  - Workflow: Quotes submit as "Pending" -> Admin approves/rejects.
  - Bulk moderation actions.
  - Flagging system for user-reported content.

- **Voting & Interaction**
  - Upvote/Downvote system.
  - Database-backed IP tracking to ensure 1 vote per IP per quote.
  - Cookie-less architecture for better privacy and voting integrity.

- **User Interface**
  - Responsive, clean design.
  - **Dark Mode** / Light Mode toggle (persists via local storage).
  - Search functionality (Web and API).
  - Random quote generator.

- **security**
  - CSRF Protection (WTF-CSRF).
  - Secure Headers (CSP, HSTS, X-Frame-Options) configurable via JSON.
  - SQL Injection protection via SQLAlchemy ORM.
  - Input sanitization.

## Prerequisites

- Python 3.8+
- SQLite (included)

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/ircquotes.git
   cd ircquotes
   ```

2. **Set up a virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the application secrets:**
   Create a secret key file in the instance folder.
   ```bash
   mkdir -p instance
   echo "your-super-secret-random-string" > instance/flask_secret_key
   ```

5. **Initialize the database:**
   Run the setup script to create the SQLite database and tables.
   ```bash
   python create_fresh_db.py
   ```
   *Note: This will ask for confirmation before overwriting an existing database.*

## Configuration

The application is fully configurable via `config.json`. You can adjust:
- Database settings (pool size, timeouts).
- Security headers and CSRF settings.
- App behavior (Quotes per page, max length, auto-approve toggle).
- Logging levels.

For a detailed explanation of every setting, see [CONFIG_GUIDE.md](CONFIG_GUIDE.md).

### Admin Credentials
The default admin user is configured in `config.json`. To generate a new password hash for the config file, use the utility script:

```bash
python generate_password.py
# Enter password when prompted, then copy the hash to config.json
```

## Running the Application

### Development
For local development with debug mode enabled:

```bash
python app.py
```
Access the app at `http://127.0.0.1:6969`.

### Production
For production environments, use the included Gunicorn wrapper or a WSGI server of your choice.

```bash
python production.py
```
Or directly with Gunicorn:
```bash
gunicorn -c production.py app:app
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed Nginx and Systemd configuration examples.

## Testing

The project includes a comprehensive test suite using `pytest`.

```bash
pytest
```
*Note: The tests use a file-swapping mechanism to safely backup your production database while running tests against a temporary one.*

## API Documentation

The application exposes a JSON API for third-party integrations.

- `GET /api/quotes` - List quotes (paginated)
- `GET /api/quotes/<id>` - Get specific quote
- `GET /api/random` - Get a random quote
- `GET /api/search?q=term` - Search quotes
- `GET /api/stats` - Database statistics

## License

See [LICENSE](LICENSE) file for details.
