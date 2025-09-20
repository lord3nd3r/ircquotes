# Gunicorn configuration file for ircquotes
import multiprocessing
import json
import os

# Load configuration from config.json
def load_app_config():
    config_file = os.path.join(os.path.dirname(__file__), 'config.json')
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except:
        # Fallback to defaults if config.json not found
        return {
            "app": {"host": "0.0.0.0", "port": 5050}
        }

app_config = load_app_config()

# Server socket - use config.json values
host = app_config.get('app', {}).get('host', '0.0.0.0')
port = app_config.get('app', {}).get('port', 5050)
bind = f"{host}:{port}"
backlog = 2048

# Worker processes - use config.json values
workers = app_config.get('gunicorn', {}).get('workers', multiprocessing.cpu_count() * 2 + 1)
worker_class = "sync"
worker_connections = 1000
timeout = app_config.get('gunicorn', {}).get('timeout', 30)
keepalive = app_config.get('gunicorn', {}).get('keepalive', 5)

# Restart workers after this many requests, to help prevent memory leaks
max_requests = app_config.get('gunicorn', {}).get('max_requests', 1000)
max_requests_jitter = 100

# Preload app for better performance
preload_app = app_config.get('gunicorn', {}).get('preload', True)

# Logging
accesslog = "-"  # Log to stdout
errorlog = "-"   # Log to stderr
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = 'ircquotes'

# Preload app for better performance
preload_app = True

# Security
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190

# SSL (uncomment and configure for HTTPS)
# keyfile = '/path/to/keyfile'
# certfile = '/path/to/certfile'