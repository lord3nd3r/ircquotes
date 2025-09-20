from flask import Flask, render_template, request, redirect, url_for, flash, abort, make_response, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect
import datetime
import json
import random
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from werkzeug.middleware.proxy_fix import ProxyFix  # Import ProxyFix
import logging
from sqlalchemy import event
from sqlalchemy.engine import Engine
import sqlite3
from config_loader import config  # Import configuration system

def get_real_ip():
    """
    Get the real client IP address considering Cloudflare and nginx reverse proxy.
    Checks headers in order of priority:
    1. CF-Connecting-IP (Cloudflare's real IP header)
    2. X-Forwarded-For (standard proxy header)
    3. X-Real-IP (nginx real IP header)
    4. request.remote_addr (fallback)
    """
    # Cloudflare provides the real IP in CF-Connecting-IP header
    cf_ip = request.headers.get('CF-Connecting-IP')
    if cf_ip:
        return cf_ip
    
    # Check X-Forwarded-For (may contain multiple IPs, first is original client)
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        # Take the first IP in the chain (original client)
        return forwarded_for.split(',')[0].strip()
    
    # Check X-Real-IP (nginx header)
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip
    
    # Fallback to request.remote_addr or default
    return request.remote_addr or '127.0.0.1'

# Configure SQLite for better concurrency
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        # Set WAL mode for better concurrency
        cursor.execute("PRAGMA journal_mode=WAL")
        # Set timeout for locked database
        cursor.execute("PRAGMA busy_timeout=30000")  # 30 seconds
        # Optimize for performance
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA cache_size=1000")
        cursor.execute("PRAGMA temp_store=memory")
        cursor.close()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = config.database_uri
app.config['SECRET_KEY'] = open("instance/flask_secret_key", "r").read().strip()

# Configure secure session settings from config
app.config['SESSION_COOKIE_SECURE'] = config.get('security.session_cookie_secure', False)
app.config['SESSION_COOKIE_HTTPONLY'] = config.get('security.session_cookie_httponly', True)
app.config['SESSION_COOKIE_SAMESITE'] = config.get('security.session_cookie_samesite', 'Lax')

# Configure CSRF protection from config
app.config['WTF_CSRF_ENABLED'] = config.csrf_enabled
app.config['WTF_CSRF_TIME_LIMIT'] = config.get('security.csrf_time_limit')
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_timeout': config.get('database.pool_timeout', 20),
    'pool_recycle': config.get('database.pool_recycle', -1),
    'pool_pre_ping': config.get('database.pool_pre_ping', True)
}

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Exempt API endpoints from CSRF protection
csrf.exempt('get_all_quotes')
csrf.exempt('get_quote')
csrf.exempt('get_random_quote')
csrf.exempt('get_top_quotes')
csrf.exempt('search_quotes')
csrf.exempt('get_stats')

# Initialize rate limiter with custom IP detection
limiter = Limiter(app, key_func=get_real_ip)

db = SQLAlchemy(app)

# Apply ProxyFix middleware for Cloudflare + nginx setup
# x_for=2: nginx (1) + Cloudflare (1) = 2 proxies in X-Forwarded-For chain
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=2, x_proto=1, x_host=1, x_port=1, x_prefix=1)

# Initialize Argon2 password hasher
ph = PasswordHasher()

# Configure logging from config
logging.basicConfig(
    level=getattr(logging, config.logging_level),
    format=config.get('logging.format', '%(asctime)s [%(levelname)s] %(message)s')
)

# Add security headers from config
@app.after_request
def add_security_headers(response):
    headers = config.get('security.security_headers', {})
    if headers.get('x_content_type_options'):
        response.headers['X-Content-Type-Options'] = headers['x_content_type_options']
    if headers.get('x_frame_options'):
        response.headers['X-Frame-Options'] = headers['x_frame_options']
    if headers.get('x_xss_protection'):
        response.headers['X-XSS-Protection'] = headers['x_xss_protection']
    if headers.get('strict_transport_security'):
        response.headers['Strict-Transport-Security'] = headers['strict_transport_security']
    if headers.get('content_security_policy'):
        response.headers['Content-Security-Policy'] = headers['content_security_policy']
    return response

# Admin credentials from config
ADMIN_CREDENTIALS = {
    'username': config.admin_username,
    'password': config.admin_password_hash
}

# Define the Quote model
class Quote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    votes = db.Column(db.Integer, default=0)
    date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    status = db.Column(db.Integer, default=0)  # 0 = pending, 1 = approved, 2 = rejected
    ip_address = db.Column(db.String(45))  # Store IPv4 and IPv6 addresses
    user_agent = db.Column(db.String(255))  # Store user-agent strings
    submitted_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    flag_count = db.Column(db.Integer, default=0)  # Track how many times quote has been flagged

# Home route to display quotes
@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    quotes = Quote.query.filter_by(status=1).order_by(Quote.date.desc()).paginate(page=page, per_page=5)
    
    # Get the count of approved and pending quotes
    approved_count = Quote.query.filter_by(status=1).count()
    pending_count = Quote.query.filter_by(status=0).count()
    
    return render_template('index.html', quotes=quotes, approved_count=approved_count, pending_count=pending_count)

# Separate route for submitting quotes
@app.route('/submit', methods=['GET', 'POST'])
@limiter.limit(config.get('rate_limiting.endpoints.submit', '5 per minute'))
def submit():
    if request.method == 'POST':
        quote_text = request.form.get('quote')
        if not quote_text:
            flash("Oops! Your quote seems to be empty. Please enter some text before submitting.", 'error')
            return redirect(url_for('submit'))
        
        # Input validation and length limits from config
        quote_text = quote_text.strip()
        min_length = config.min_quote_length
        max_length = config.max_quote_length
        
        if len(quote_text) < min_length:
            flash(f"Your quote is too short. Please enter at least {min_length} characters.", 'error')
            return redirect(url_for('submit'))
        
        if len(quote_text) > max_length:
            flash(f"Your quote is too long. Please keep it under {max_length} characters.", 'error')
            return redirect(url_for('submit'))
        
        # Basic content validation (no scripts or dangerous content)
        if not config.get('quotes.allow_html', False):
            if '<script' in quote_text.lower() or 'javascript:' in quote_text.lower():
                flash("Invalid content detected. Please remove any script tags or JavaScript.", 'error')
                return redirect(url_for('submit'))

        ip_address = get_real_ip()  # Get the real user's IP address
        user_agent = request.headers.get('User-Agent')  # Get the user's browser info

        new_quote = Quote(text=quote_text, ip_address=ip_address, user_agent=user_agent)

        try:
            db.session.add(new_quote)
            db.session.commit()
            flash("Thanks! Your quote has been submitted and is awaiting approval by our moderators.", 'success')
        except Exception as e:
            db.session.rollback()
            flash("Sorry, something went wrong while submitting your quote. Please try again in a moment.", 'error')

        return redirect(url_for('index'))

    # Get the count of approved and pending quotes
    approved_count = Quote.query.filter_by(status=1).count()
    pending_count = Quote.query.filter_by(status=0).count()

    return render_template('submit.html', approved_count=approved_count, pending_count=pending_count)

@app.route('/vote/<int:id>/<action>')
@limiter.limit("20 per minute")
def vote(id, action):
    quote = Quote.query.get_or_404(id)

    # Retrieve vote history from the cookie
    vote_cookie = request.cookies.get('votes')
    if vote_cookie:
        try:
            vote_data = json.loads(vote_cookie)
        except (json.JSONDecodeError, ValueError):
            # If cookie is corrupted, start fresh
            vote_data = {}
    else:
        vote_data = {}

    message = ""
    # If no prior vote, apply the new vote
    if str(id) not in vote_data:
        if action == 'upvote':
            quote.votes += 1
            vote_data[str(id)] = 'upvote'
        elif action == 'downvote':
            quote.votes -= 1
            vote_data[str(id)] = 'downvote'
        message = "Thank you for voting!"
    
    else:
        previous_action = vote_data[str(id)]

        if previous_action == action:
            # If the user clicks the same action again, undo the vote
            if action == 'upvote':
                quote.votes -= 1
            elif action == 'downvote':
                quote.votes += 1
            del vote_data[str(id)]  # Remove the vote record (undo)
            message = "Your vote has been undone."
        else:
            # If the user switches votes (upvote -> downvote or vice versa)
            if previous_action == 'upvote' and action == 'downvote':
                quote.votes -= 2  # Undo upvote (+1) and apply downvote (-1)
                vote_data[str(id)] = 'downvote'
            elif previous_action == 'downvote' and action == 'upvote':
                quote.votes += 2  # Undo downvote (-1) and apply upvote (+1)
                vote_data[str(id)] = 'upvote'
            message = "Your vote has been changed."

    # Save the updated vote data to the cookie
    try:
        db.session.commit()
        
        # Check if it's an AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            # Return JSON response for AJAX
            resp = make_response(jsonify({
                'success': True,
                'votes': quote.votes,
                'user_vote': vote_data.get(str(id)),
                'message': message
            }))
            resp.set_cookie('votes', json.dumps(vote_data), max_age=60*60*24*365)
            return resp
        else:
            # Traditional redirect for non-AJAX requests
            flash(message, 'success')
            page = request.args.get('page', 1)
            resp = make_response(redirect(url_for('browse', page=page)))
            resp.set_cookie('votes', json.dumps(vote_data), max_age=60*60*24*365)
            return resp
    except Exception as e:
        db.session.rollback()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': False,
                'message': f"Error while voting: {e}"
            }), 500
        else:
            flash(f"Error while voting: {e}", 'error')
            page = request.args.get('page', 1)
            return redirect(url_for('browse', page=page))

# Route for displaying a random quote
@app.route('/random')
def random_quote():
    approved_count = Quote.query.filter_by(status=1).count()
    pending_count = Quote.query.filter_by(status=0).count()
    count = Quote.query.filter_by(status=1).count()  # Only count approved quotes

    if count == 0:
        flash("No quotes have been approved yet. Check back later or submit the first one!", 'error')
        return redirect(url_for('index'))

    # Use offset to get a random quote from approved quotes
    random_offset = random.randint(0, count - 1)
    random_quote = Quote.query.filter_by(status=1).offset(random_offset).first()

    return render_template('random.html', quote=random_quote, approved_count=approved_count, pending_count=pending_count)


@app.route('/<int:id>')
def quote_homepathid(id):
    quote = Quote.query.get_or_404(id)
    return render_template('quote.html', quote=quote)

@app.route('/quote')
def quote():
    quote_id = request.args.get('id')
    if not quote_id:
        flash("Please enter a quote number to view that specific quote.", 'error')
        return redirect(url_for('browse'))
    
    quote = Quote.query.get_or_404(quote_id)
    return render_template('quote.html', quote=quote)

@app.route('/faq')
def faq():
    return render_template('faq.html')

# Flag/Report a quote route
@app.route('/flag/<int:id>')
@limiter.limit("10 per minute")
def flag_quote(id):
    quote = Quote.query.get_or_404(id)
    
    # Increment flag count
    quote.flag_count += 1
    
    try:
        db.session.commit()
        message = 'Quote has been flagged for review. Thank you for helping keep the site clean!'
        
        # Check if it's an AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': True,
                'message': message,
                'flag_count': quote.flag_count
            })
        else:
            flash(message, 'success')
    except Exception as e:
        db.session.rollback()
        error_message = 'Error flagging quote. Please try again.'
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': False,
                'message': error_message
            }), 500
        else:
            flash(error_message, 'error')
    
    # For non-AJAX requests, redirect back to the same page
    referer = request.headers.get('Referer')
    if referer and any(path in referer for path in ['/browse', '/quote', '/random', '/search']):
        return redirect(referer)
    else:
        return redirect(url_for('browse'))

# Admin login route
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit(config.get('rate_limiting.endpoints.login', '5 per minute'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if the username is correct and verify the password using Argon2
        if username == ADMIN_CREDENTIALS['username']:
            try:
                ph.verify(ADMIN_CREDENTIALS['password'], password)  # Verify password using Argon2
                session['admin'] = True
                flash('Welcome back! You are now logged in as administrator.', 'success')
                return redirect(url_for('modapp'))
            except VerifyMismatchError:
                flash('The password you entered is incorrect. Please check your password and try again.', 'danger')
        else:
            flash('The username you entered is not recognized. Please check your username and try again.', 'danger')
    
    return render_template('login.html')

# Admin panel route (accessible only to logged-in admins)
@app.route('/modapp')
@limiter.limit("20 per minute")
def modapp():
    if not session.get('admin'):
        flash('Access denied. Please log in with administrator credentials to access the moderation panel.', 'danger')
        return redirect(url_for('login'))

    # Apply filtering (pending, approved, rejected, flagged)
    filter_status = request.args.get('filter', 'pending')
    page = request.args.get('page', 1, type=int)

    if filter_status == 'approved':
        quotes = Quote.query.filter_by(status=1).order_by(Quote.date.desc()).paginate(page=page, per_page=10)
    elif filter_status == 'rejected':
        quotes = Quote.query.filter_by(status=2).order_by(Quote.date.desc()).paginate(page=page, per_page=10)
    elif filter_status == 'flagged':
        # Show quotes with flag_count > 0, ordered by flag count (highest first)
        quotes = Quote.query.filter(Quote.flag_count > 0).order_by(Quote.flag_count.desc(), Quote.date.desc()).paginate(page=page, per_page=10)
    else:  # Default to pending
        quotes = Quote.query.filter_by(status=0).order_by(Quote.date.desc()).paginate(page=page, per_page=10)

    # Get counts for each status
    approved_count = Quote.query.filter_by(status=1).count()
    pending_count = Quote.query.filter_by(status=0).count()
    rejected_count = Quote.query.filter_by(status=2).count()
    flagged_count = Quote.query.filter(Quote.flag_count > 0).count()

    return render_template('modapp.html', quotes=quotes, filter_status=filter_status,
                           approved_count=approved_count, pending_count=pending_count,
                           rejected_count=rejected_count, flagged_count=flagged_count)


# Bulk actions route for modapp
@app.route('/modapp/bulk', methods=['POST'])
@limiter.limit("10 per minute")
def modapp_bulk():
    if not session.get('admin'):
        flash('Access denied. Administrator login required for bulk actions.', 'danger')
        return redirect(url_for('login'))
    
    action = request.form.get('action')
    quote_ids = request.form.getlist('quote_ids')
    
    if not quote_ids:
        flash('Please select at least one quote before performing a bulk action.', 'error')
        return redirect(url_for('modapp'))
    
    if not action or action not in ['approve', 'reject', 'delete', 'clear_flags']:
        flash('The requested action is not supported. Please try again or contact support.', 'error')
        return redirect(url_for('modapp'))
    
    success_count = 0
    
    try:
        for quote_id in quote_ids:
            quote = Quote.query.get(int(quote_id))
            if quote:
                if action == 'approve':
                    quote.status = 1
                    success_count += 1
                elif action == 'reject':
                    quote.status = 2
                    success_count += 1
                elif action == 'delete':
                    db.session.delete(quote)
                    success_count += 1
                elif action == 'clear_flags':
                    quote.flag_count = 0
                    success_count += 1
        
        db.session.commit()
        
        if action == 'clear_flags':
            flash(f'Successfully cleared flags on {success_count} quote(s).', 'success')
        else:
            flash(f'Successfully {action}d {success_count} quote(s).', 'success')
            
    except Exception as e:
        db.session.rollback()
        flash(f'Error performing bulk action: {str(e)}', 'error')
    
    return redirect(url_for('modapp'))


# Helper function to approve a quote
def approve_quote(quote_id):
    quote = Quote.query.get(quote_id)
    if quote and quote.status != 1:  # Only approve if not already approved
        quote.status = 1  # Approved
        db.session.commit()

# Helper function to reject a quote
def reject_quote(quote_id):
    quote = Quote.query.get(quote_id)
    if quote and quote.status != 2:  # Only reject if not already rejected
        quote.status = 'rejected'
        db.session.commit()

# Helper function to delete a quote
def delete_quote(quote_id):
    quote = Quote.query.get(quote_id)
    if quote:
        db.session.delete(quote)
        db.session.commit()

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '').strip()  # Get the search query
    quotes = []

    # Query counts of approved and pending quotes
    approved_count = Quote.query.filter_by(status=1).count()
    pending_count = Quote.query.filter_by(status=0).count()

    if query:
        # Perform text search in quotes using safe parameterized query
        quotes = Quote.query.filter(Quote.text.contains(query), Quote.status == 1).all()

    return render_template('search.html', quotes=quotes, query=query, approved_count=approved_count, pending_count=pending_count)

@app.route('/read', methods=['GET'])
def read_quote():
    quote_id = request.args.get('id', type=int)  # Get the quote number
    
    if not quote_id:
        flash("Please enter a valid quote number to search for that specific quote.", 'error')
        return redirect(url_for('search'))

    # Find the quote by ID (only approved quotes)
    quote = Quote.query.filter_by(id=quote_id, status=1).first()

    if quote:
        return render_template('quote.html', quote=quote)
    else:
        flash(f"No quote found with ID {quote_id}", 'error')
        return redirect(url_for('search'))

# Route for browsing approved quotes
@app.route('/browse', methods=['GET'])
def browse():
    # Query the counts of approved and pending quotes
    approved_count = Quote.query.filter_by(status=1).count()
    pending_count = Quote.query.filter_by(status=0).count()

    # Pagination setup with config
    page = request.args.get('page', 1, type=int)
    per_page = config.quotes_per_page
    quotes = Quote.query.filter_by(status=1).order_by(Quote.date.desc()).paginate(page=page, per_page=per_page)

    # Pass the counts and the quotes to the template
    return render_template('browse.html', quotes=quotes, approved_count=approved_count, pending_count=pending_count)


# Approve a quote (admin only)
@app.route('/approve/<int:id>')
@limiter.limit("30 per minute")
def approve(id):
    if not session.get('admin'):
        return redirect(url_for('login'))

    quote = Quote.query.get_or_404(id)
    quote.status = 1
    db.session.commit()

    # Redirect back to the same page
    page = request.args.get('page', 1)
    return redirect(url_for('modapp', page=page))

# Reject a quote (admin only)
@app.route('/reject/<int:id>')
@limiter.limit("30 per minute")
def reject(id):
    if not session.get('admin'):
        return redirect(url_for('login'))

    quote = Quote.query.get_or_404(id)
    quote.status = 2  # 2 = rejected
    db.session.commit()
    return redirect(url_for('modapp'))

# Delete a quote (admin only)
@app.route('/delete/<int:id>')
@limiter.limit("20 per minute")
def delete(id):
    if not session.get('admin'):
        return redirect(url_for('login'))

    quote = Quote.query.get_or_404(id)
    db.session.delete(quote)
    db.session.commit()
    return redirect(url_for('modapp'))

# Clear flags from a quote (admin only)
@app.route('/clear_flags/<int:id>')
def clear_flags(id):
    if not session.get('admin'):
        return redirect(url_for('login'))

    quote = Quote.query.get_or_404(id)
    quote.flag_count = 0
    db.session.commit()
    flash(f'Flags cleared for quote #{id}. Quote remains {["pending", "approved", "rejected"][quote.status]}.', 'success')
    
    # Redirect back to the same page with filter preserved
    page = request.args.get('page', 1)
    filter_status = request.args.get('filter', 'flagged')
    return redirect(url_for('modapp', page=page, filter=filter_status))

# Admin logout route
@app.route('/logout')
def logout():
    session.pop('admin', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

# Automatically create the database tables using app context
with app.app_context():
    db.create_all()
    
    # Add flag_count column if it doesn't exist (for existing databases)
    try:
        # Try to access flag_count on a quote to test if column exists
        test_query = db.session.execute(db.text("SELECT flag_count FROM quote LIMIT 1"))
    except Exception as e:
        if "no such column" in str(e).lower():
            # Add the missing column using raw SQL
            db.session.execute(db.text("ALTER TABLE quote ADD COLUMN flag_count INTEGER DEFAULT 0"))
            db.session.commit()
            print("Added flag_count column to existing database")

# Initialize CORS for cross-origin API access
CORS(app)

# API to get all approved quotes with pagination
@app.route('/api/quotes', methods=['GET'])
@limiter.limit("60 per minute")
def get_all_quotes():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)  # Max 100 per page
    sort_by = request.args.get('sort', 'date')  # date, votes, id
    order = request.args.get('order', 'desc')  # asc, desc
    
    # Build query
    query = Quote.query.filter_by(status=1)
    
    # Apply sorting
    if sort_by == 'votes':
        if order == 'asc':
            query = query.order_by(Quote.votes.asc())
        else:
            query = query.order_by(Quote.votes.desc())
    elif sort_by == 'id':
        if order == 'asc':
            query = query.order_by(Quote.id.asc())
        else:
            query = query.order_by(Quote.id.desc())
    else:  # Default to date
        if order == 'asc':
            query = query.order_by(Quote.date.asc())
        else:
            query = query.order_by(Quote.date.desc())
    
    # Paginate
    quotes = query.paginate(page=page, per_page=per_page, error_out=False)
    
    quote_list = [{
        'id': quote.id,
        'text': quote.text,
        'votes': quote.votes
    } for quote in quotes.items]
    
    return jsonify({
        'quotes': quote_list,
        'pagination': {
            'page': quotes.page,
            'pages': quotes.pages,
            'per_page': quotes.per_page,
            'total': quotes.total,
            'has_next': quotes.has_next,
            'has_prev': quotes.has_prev
        }
    }), 200

# API to get a specific quote by ID
@app.route('/api/quotes/<int:id>', methods=['GET'])
@limiter.limit("120 per minute")
def get_quote(id):
    quote = Quote.query.filter_by(id=id, status=1).first_or_404()  # Only approved quotes
    quote_data = {
        'id': quote.id,
        'text': quote.text,
        'votes': quote.votes
    }
    return jsonify(quote_data), 200

# API to get a random approved quote
@app.route('/api/random', methods=['GET'])
@limiter.limit("30 per minute")
def get_random_quote():
    count = Quote.query.filter_by(status=1).count()
    if count == 0:
        return jsonify({"error": "No approved quotes available"}), 404
    
    random_offset = random.randint(0, count - 1)
    random_quote = Quote.query.filter_by(status=1).offset(random_offset).first()
    
    quote_data = {
        'id': random_quote.id,
        'text': random_quote.text,
        'votes': random_quote.votes
    }
    return jsonify(quote_data), 200

# API to get the top quotes by vote count
@app.route('/api/top', methods=['GET'])
@limiter.limit("30 per minute")
def get_top_quotes():
    limit = min(request.args.get('limit', 10, type=int), 100)  # Default 10, max 100
    min_votes = request.args.get('min_votes', 0, type=int)  # Minimum vote threshold
    
    top_quotes = Quote.query.filter(Quote.status == 1, Quote.votes >= min_votes).order_by(Quote.votes.desc()).limit(limit).all()
    quote_list = [{
        'id': quote.id,
        'text': quote.text,
        'votes': quote.votes
    } for quote in top_quotes]
    
    return jsonify({
        'quotes': quote_list,
        'meta': {
            'limit': limit,
            'min_votes': min_votes,
            'count': len(quote_list)
        }
    }), 200

# API to search for quotes with pagination
@app.route('/api/search', methods=['GET'])
@limiter.limit("40 per minute")
def search_quotes():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify({"error": "No search term provided"}), 400
    
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)  # Max 100 per page
    
    # Search in approved quotes with pagination using safe parameterized query
    quotes = Quote.query.filter(
        Quote.text.contains(query), 
        Quote.status == 1
    ).order_by(Quote.votes.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    if not quotes.items:
        return jsonify({
            "error": "No quotes found for search term",
            "search_term": query,
            "total_results": 0
        }), 404

    quote_list = [{
        'id': quote.id,
        'text': quote.text,
        'votes': quote.votes
    } for quote in quotes.items]
    
    return jsonify({
        'quotes': quote_list,
        'search_term': query,
        'pagination': {
            'page': quotes.page,
            'pages': quotes.pages,
            'per_page': quotes.per_page,
            'total': quotes.total,
            'has_next': quotes.has_next,
            'has_prev': quotes.has_prev
        }
    }), 200

# API to get quote statistics
@app.route('/api/stats', methods=['GET'])
@limiter.limit("20 per minute")
def get_stats():
    total_quotes = Quote.query.count()
    approved_quotes = Quote.query.filter_by(status=1).count()
    pending_quotes = Quote.query.filter_by(status=0).count()
    rejected_quotes = Quote.query.filter_by(status=2).count()
    flagged_quotes = Quote.query.filter(Quote.flag_count > 0).count()
    
    # Vote statistics
    top_voted = Quote.query.filter_by(status=1).order_by(Quote.votes.desc()).first()
    total_votes = db.session.query(db.func.sum(Quote.votes)).filter_by(status=1).scalar() or 0
    avg_votes = db.session.query(db.func.avg(Quote.votes)).filter_by(status=1).scalar() or 0
    
    return jsonify({
        'total_quotes': total_quotes,
        'approved_quotes': approved_quotes,
        'pending_quotes': pending_quotes,
        'rejected_quotes': rejected_quotes,
        'flagged_quotes': flagged_quotes,
        'vote_stats': {
            'total_votes': int(total_votes),
            'average_votes': round(float(avg_votes), 2),
            'highest_voted': {
                'id': top_voted.id if top_voted else None,
                'votes': top_voted.votes if top_voted else 0,
                'text_preview': top_voted.text[:100] + '...' if top_voted and len(top_voted.text) > 100 else (top_voted.text if top_voted else None)
            }
        }
    }), 200

# API documentation endpoint
@app.route('/api/docs', methods=['GET'])
@limiter.limit("10 per minute")
def api_docs():
    docs = {
        "ircquotes.org API Documentation": {
            "version": "1.0",
            "description": "Read-only API for accessing IRC quotes",
            "base_url": request.url_root + "api/",
            "endpoints": {
                "/api/quotes": {
                    "method": "GET",
                    "description": "Get paginated list of approved quotes",
                    "parameters": {
                        "page": "Page number (default: 1)",
                        "per_page": "Results per page (default: 20, max: 100)",
                        "sort": "Sort by 'date', 'votes', or 'id' (default: 'date')",
                        "order": "Sort order 'asc' or 'desc' (default: 'desc')"
                    },
                    "example": "/api/quotes?page=1&per_page=10&sort=votes&order=desc"
                },
                "/api/quotes/<id>": {
                    "method": "GET",
                    "description": "Get a specific quote by ID",
                    "parameters": {
                        "id": "Quote ID (required)"
                    },
                    "example": "/api/quotes/12345"
                },
                "/api/random": {
                    "method": "GET",
                    "description": "Get a random approved quote",
                    "parameters": "None",
                    "example": "/api/random"
                },
                "/api/top": {
                    "method": "GET",
                    "description": "Get top-voted quotes",
                    "parameters": {
                        "limit": "Number of quotes to return (default: 10, max: 100)",
                        "min_votes": "Minimum vote threshold (default: 0)"
                    },
                    "example": "/api/top?limit=20&min_votes=5"
                },
                "/api/search": {
                    "method": "GET",
                    "description": "Search quotes by text content",
                    "parameters": {
                        "q": "Search query (required)",
                        "page": "Page number (default: 1)",
                        "per_page": "Results per page (default: 20, max: 100)"
                    },
                    "example": "/api/search?q=linux&page=1&per_page=10"
                },
                "/api/stats": {
                    "method": "GET",
                    "description": "Get quote database statistics",
                    "parameters": "None",
                    "example": "/api/stats"
                }
            },
            "response_format": {
                "quotes": "Array of quote objects",
                "quote_object": {
                    "id": "Quote ID",
                    "text": "Quote text content",
                    "votes": "Current vote count",
                    "date": "Creation date (YYYY-MM-DD)",
                    "datetime": "Full timestamp (YYYY-MM-DD HH:MM:SS)"
                },
                "pagination": {
                    "page": "Current page number",
                    "pages": "Total pages",
                    "per_page": "Results per page",
                    "total": "Total results",
                    "has_next": "Boolean - has next page",
                    "has_prev": "Boolean - has previous page"
                }
            },
            "notes": [
                "All endpoints return only approved quotes",
                "Rate limiting may apply to prevent abuse",
                "All responses are in JSON format",
                "CORS is enabled for cross-origin requests"
            ]
        }
    }
    return jsonify(docs), 200

# API to submit a new quote (DISABLED for abuse prevention)
@app.route('/api/submit', methods=['POST'])
@limiter.limit("5 per minute")
def submit_quote():
    return jsonify({
        "error": "Quote submission via API is currently disabled to prevent abuse.",
        "message": "Please use the web interface at /submit to submit quotes.",
        "web_submit_url": request.url_root + "submit"
    }), 403

# Create tables if they don't exist
with app.app_context():
    db.create_all()

# For Gunicorn deployment
if __name__ == '__main__':
    # This is only used for local development testing
    # In production, use: gunicorn -w 4 -b 0.0.0.0:5050 app:app
    print("Warning: Using Flask development server. Use Gunicorn for production!")
    app.run(host='127.0.0.1', port=5050, debug=False)
