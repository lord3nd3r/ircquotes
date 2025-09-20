#!/bin/bash

# ircquotes production server setup script
# Run this after cloning the repository

echo "Setting up ircquotes on production server..."

# Create instance directory
echo "Creating instance directory..."
mkdir -p instance

# Generate secret key
echo "Generating Flask secret key..."
python3 -c "import secrets; print(secrets.token_hex(32))" > instance/flask_secret_key

# Create empty database file
echo "Creating database file..."
touch instance/quotes.db

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
echo "2. Start the application:"
echo "   source .venv/bin/activate"
echo "   gunicorn --config gunicorn.conf.py app:app"
echo ""
echo "3. Or run in development mode:"
echo "   python app.py"