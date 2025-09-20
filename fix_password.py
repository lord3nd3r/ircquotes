#!/usr/bin/env python3
"""
Fix corrupted admin password hash in config.json
"""

import json
from argon2 import PasswordHasher
import getpass

def fix_admin_password():
    """Fix the corrupted admin password hash"""
    
    print("Current admin password hash appears to be corrupted.")
    print("Let's generate a new one...")
    
    # Get new password
    password = getpass.getpass("Enter new admin password: ")
    confirm = getpass.getpass("Confirm password: ")
    
    if password != confirm:
        print("Passwords don't match!")
        return
    
    # Generate new hash
    ph = PasswordHasher()
    new_hash = ph.hash(password)
    
    # Load current config
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
    except Exception as e:
        print(f"Error reading config.json: {e}")
        return
    
    # Update the password hash
    if 'admin' not in config:
        config['admin'] = {}
    
    config['admin']['password_hash'] = new_hash
    
    # Save config
    try:
        with open('config.json', 'w') as f:
            json.dump(config, f, indent=2)
        
        print("\nPassword hash updated successfully!")
        print(f"New hash: {new_hash}")
        print("\nRestart the application for changes to take effect.")
        
    except Exception as e:
        print(f"Error saving config.json: {e}")

if __name__ == "__main__":
    fix_admin_password()