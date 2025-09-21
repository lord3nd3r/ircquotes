#!/usr/bin/env python3
"""
Password hash generator for ircquotes admin.
Generates Argon2 password hashes for secure storage.
"""

from argon2 import PasswordHasher
import getpass
import sys

def generate_password_hash():
    """Generate an Argon2 password hash."""
    ph = PasswordHasher()
    
    if len(sys.argv) > 1:
        # Password provided as argument
        password = sys.argv[1]
    else:
        # Prompt for password securely
        password = getpass.getpass("Enter admin password: ")
        confirm = getpass.getpass("Confirm password: ")
        
        if password != confirm:
            print("Passwords don't match!")
            return
    
    # Generate hash
    hash_value = ph.hash(password)
    
    print("\nGenerated password hash:")
    print(hash_value)
    print("\nTo set this as admin password:")
    print("1. Open config.json in a text editor")
    print("2. Find the 'admin' section")
    print("3. Replace the 'password_hash' value with:")
    print(f'   "{hash_value}"')
    print("4. Save the file and restart the application")

if __name__ == "__main__":
    generate_password_hash()