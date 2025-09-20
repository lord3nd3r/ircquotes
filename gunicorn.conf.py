# Gunicorn configuration file for ircquotes
import multiprocessing

# Server socket
bind = "0.0.0.0:5050"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 5

# Restart workers after this many requests, to help prevent memory leaks
max_requests = 1000
max_requests_jitter = 100

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