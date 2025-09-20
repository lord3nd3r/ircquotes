#!/usr/bin/env python3
"""
Configuration management utility for ircquotes.
Allows you to view and update configuration values easily.
"""

import json
import sys
from config_loader import config

def show_config():
    """Display current configuration."""
    print("Current Configuration:")
    print("=" * 50)
    print(f"App Name: {config.app_name}")
    print(f"Host: {config.app_host}")
    print(f"Port: {config.app_port}")
    print(f"Debug Mode: {config.debug_mode}")
    print(f"Database URI: {config.database_uri}")
    print(f"CSRF Enabled: {config.csrf_enabled}")
    print(f"Rate Limiting: {config.rate_limiting_enabled}")
    print(f"Quotes per Page: {config.quotes_per_page}")
    print(f"Min Quote Length: {config.min_quote_length}")
    print(f"Max Quote Length: {config.max_quote_length}")
    print(f"Admin Username: {config.admin_username}")
    print(f"Logging Level: {config.logging_level}")
    print("=" * 50)

def update_config(key, value):
    """Update a configuration value."""
    try:
        # Load current config
        with open('config.json', 'r') as f:
            data = json.load(f)
        
        # Navigate to the key using dot notation
        keys = key.split('.')
        current = data
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        # Convert value to appropriate type
        if value.lower() == 'true':
            value = True
        elif value.lower() == 'false':
            value = False
        elif value.isdigit():
            value = int(value)
        elif value.replace('.', '').isdigit():
            value = float(value)
        
        # Set the value
        current[keys[-1]] = value
        
        # Save back to file
        with open('config.json', 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"Updated {key} = {value}")
        print("Restart the application for changes to take effect.")
        
    except Exception as e:
        print(f"Error updating configuration: {e}")

def main():
    if len(sys.argv) == 1:
        show_config()
    elif len(sys.argv) == 3:
        key, value = sys.argv[1], sys.argv[2]
        update_config(key, value)
    else:
        print("Usage:")
        print("  python config_manager.py                    # Show current config")
        print("  python config_manager.py <key> <value>      # Update config value")
        print()
        print("Examples:")
        print("  python config_manager.py app.port 8080")
        print("  python config_manager.py quotes.per_page 50")
        print("  python config_manager.py security.csrf_enabled false")

if __name__ == "__main__":
    main()