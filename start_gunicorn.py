#!/usr/bin/env python3
"""
Gunicorn launcher that reads configuration from config.json
"""

import json
import subprocess
import sys
from config_loader import config

def main():
    """Launch Gunicorn with settings from config.json"""
    
    # Get configuration values
    host = config.app_host
    port = config.app_port
    workers = config.get('gunicorn.workers', 4)
    
    # Build Gunicorn command
    cmd = [
        'gunicorn',
        '--bind', f'{host}:{port}',
        '--workers', str(workers),
        '--timeout', '30',
        '--keepalive', '5',
        '--max-requests', '1000',
        '--max-requests-jitter', '100',
        '--access-logfile', '-',
        '--error-logfile', '-',
        '--log-level', 'info',
        '--preload',
        'app:app'
    ]
    
    print(f"Starting Gunicorn on {host}:{port} with {workers} workers...")
    print(f"Command: {' '.join(cmd)}")
    
    # Execute Gunicorn
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error starting Gunicorn: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopping Gunicorn...")
        sys.exit(0)

if __name__ == "__main__":
    main()