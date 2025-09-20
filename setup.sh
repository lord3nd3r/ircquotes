#!/bin/bash

# ircquotes production server setup script
# Run this after cloning the repository

echo "Setting up ircquotes on production server..."

# Instance directory should already exist from git
# But create it if it doesn't
mkdir -p instance

# Generate secret key
echo "Generating Flask secret key..."
python3 -c "import secrets; print(secrets.token_hex(32))" > instance/flask_secret_key

# Create empty database file if it doesn't exist
if [ ! -f "instance/quotes.db" ]; then
    echo "Creating database file..."
    touch instance/quotes.db
fi

# Set permissions
echo "Setting file permissions..."
chmod 600 instance/flask_secret_key
chmod 664 instance/quotes.db

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv .venv

# Activate and install dependencies
echo "Installing dependencies..."
source .venv/bin/activate
pip install -r requirements.txt

# Initialize database
echo "Initializing database..."
python -c "from app import app, db; app.app_context().push(); db.create_all(); print('Database initialized successfully!')"

echo ""
echo "Setup complete! You can now:"
echo "1. Configure admin credentials:"
echo "   python generate_password.py"
echo "   python config_manager.py admin.username 'yourusername'"
echo "   python config_manager.py admin.password_hash 'generated_hash'"
echo ""
echo "2. Configure other settings:"
echo "   python config_manager.py app.port 6969"
echo "   python config_manager.py quotes.min_length 1"
echo "   python config_manager.py quotes.max_length 10000"
echo ""
echo "3. Start the application:"
echo "   source .venv/bin/activate"
echo "   gunicorn --config gunicorn.conf.py app:app"
echo ""
echo "4. Or run in development mode:"
echo "   python app.py"