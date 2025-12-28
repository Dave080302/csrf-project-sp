#!/usr/bin/env python3

from flask import Flask, request, session, redirect, url_for, render_template_string, abort
from functools import wraps
import os
import secrets
import hashlib

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configure secure session cookies
app.config.update(
    SESSION_COOKIE_SECURE=False,  # Set True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict'  # CSRF Protection: SameSite attribute
)

# Simulated database
users_db = {
    'alice': {'password': 'alice123', 'balance': 10000.00, 'email': 'alice@example.com'},
    'bob': {'password': 'bob123', 'balance': 5000.00, 'email': 'bob@example.com'},
    'charlie': {'password': 'charlie123', 'balance': 7500.00, 'email': 'charlie@example.com'}
}

transactions = []


def generate_csrf_token():
    """Generate a new CSRF token and store it in the session."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


def validate_csrf_token():
    """Validate the CSRF token from the request."""
    token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
    if not token or token != session.get('csrf_token'):
        return False
    return True


def validate_origin():
    """Validate Origin and Referer headers."""
    allowed_origins = ['http://127.0.0.1:5001', 'http://localhost:5001']
    
    origin = request.headers.get('Origin')
    referer = request.headers.get('Referer')
    
    if origin:
        if origin not in allowed_origins:
            return False
    elif referer:
        # Check if referer starts with allowed origin
        if not any(referer.startswith(o) for o in allowed_origins):
            return False
    
    return True


def csrf_protect(f):
    """Decorator to enforce CSRF protection on POST requests."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            # Validate CSRF token
            if not validate_csrf_token():
                app.logger.warning(f"CSRF token validation failed for {request.path}")
                abort(403, description="CSRF token validation failed. Request blocked.")
            
            # Validate Origin/Referer (defense in depth)
            if not validate_origin():
                app.logger.warning(f"Origin validation failed for {request.path}")
                abort(403, description="Invalid request origin. Request blocked.")
        
        return f(*args, **kwargs)
    return decorated_function


# Make csrf_token available in all templates
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token)


# HTML Templates with CSRF protection
BASE_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }} - SecureBank</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            min-height: 100vh;
            color: #fff;
        }
        .secure-banner {
            background: #27ae60;
            color: #fff;
            text-align: center;
            padding: 0.5rem;
            font-weight: bold;
        }
        .navbar {
            background: rgba(0,0,0,0.3);
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .navbar h1 { color: #27ae60; font-size: 1.5rem; }
        .navbar a {
            color: #fff;
            text-decoration: none;
            margin-left: 1rem;
            padding: 0.5rem 1rem;
            border-radius: 5px;
            transition: background 0.3s;
        }
        .navbar a:hover { background: rgba(39, 174, 96, 0.3); }
        .container { max-width: 800px; margin: 2rem auto; padding: 2rem; }
        .card {
            background: rgba(255,255,255,0.1);
            border-radius: 15px;
            padding: 2rem;
            margin-bottom: 1.5rem;
            backdrop-filter: blur(10px);
        }
        .card h2 { color: #27ae60; margin-bottom: 1rem; }
        .balance { font-size: 2.5rem; color: #27ae60; font-weight: bold; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; color: #ccc; }
        .form-group input, .form-group select {
            width: 100%;
            padding: 0.75rem;
            border: none;
            border-radius: 8px;
            background: rgba(255,255,255,0.1);
            color: #fff;
            font-size: 1rem;
        }
        .btn {
            background: #27ae60;
            color: #fff;
            border: none;
            padding: 0.75rem 2rem;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1rem;
            transition: transform 0.2s, background 0.3s;
        }
        .btn:hover { background: #2ecc71; transform: translateY(-2px); }
        .alert { padding: 1rem; border-radius: 8px; margin-bottom: 1rem; }
        .alert-success { background: rgba(39, 174, 96, 0.3); border: 1px solid #27ae60; }
        .alert-error { background: rgba(231, 76, 60, 0.3); border: 1px solid #e74c3c; }
        .security-note {
            background: rgba(39, 174, 96, 0.2);
            border: 1px solid #27ae60;
            border-radius: 8px;
            padding: 1rem;
            margin-top: 1rem;
            font-size: 0.9rem;
        }
        .protection-badge {
            display: inline-block;
            background: #27ae60;
            color: white;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            margin: 0.2rem;
        }
    </style>
</head>
<body>
    <div class="secure-banner">🔒 SECURE APPLICATION - CSRF PROTECTION ENABLED 🔒</div>
    <nav class="navbar">
        <h1>🏦 SecureBank</h1>
        <div>
            {% if session.get('logged_in') %}
                <span>Welcome, {{ session.get('username') }}</span>
                <a href="/dashboard">Dashboard</a>
                <a href="/transfer">Transfer</a>
                <a href="/settings">Settings</a>
                <a href="/logout">Logout</a>
            {% else %}
                <a href="/login">Login</a>
            {% endif %}
        </div>
    </nav>
    <div class="container">
        {{ content | safe }}
    </div>
</body>
</html>
'''

TRANSFER_CONTENT = '''
<div class="card">
    <h2>💸 Secure Transfer</h2>
    {% if success %}
    <div class="alert alert-success">{{ success }}</div>
    {% endif %}
    {% if error %}
    <div class="alert alert-error">{{ error }}</div>
    {% endif %}
    
    <!-- PROTECTED: Form includes CSRF token -->
    <form method="POST" action="/transfer">
        <!-- CSRF Token - Hidden field -->
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        
        <div class="form-group">
            <label>Recipient Username</label>
            <select name="recipient">
                {% for user in users %}
                    {% if user != current_user %}
                    <option value="{{ user }}">{{ user }}</option>
                    {% endif %}
                {% endfor %}
            </select>
        </div>
        <div class="form-group">
            <label>Amount ($)</label>
            <input type="number" name="amount" min="0.01" step="0.01" required>
        </div>
        <button type="submit" class="btn">🔒 Secure Transfer</button>
    </form>
</div>

<div class="card">
    <h2>💳 Current Balance</h2>
    <p class="balance">${{ "%.2f"|format(balance) }}</p>
</div>

<div class="security-note">
    <strong>🔒 Security Measures Active:</strong><br>
    <span class="protection-badge">CSRF Token</span>
    <span class="protection-badge">SameSite Cookie</span>
    <span class="protection-badge">Origin Validation</span>
    <span class="protection-badge">HTTPOnly Cookie</span>
    <br><br>
    <strong>How it works:</strong><br>
    • Each form includes a unique CSRF token<br>
    • Token is validated on every POST request<br>
    • Cookies use SameSite=Strict attribute<br>
    • Origin/Referer headers are validated<br>
    • Attackers cannot forge valid requests!
</div>
'''

SETTINGS_CONTENT = '''
<div class="card">
    <h2>⚙️ Account Settings</h2>
    {% if success %}
    <div class="alert alert-success">{{ success }}</div>
    {% endif %}
    
    <form method="POST" action="/settings">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <div class="form-group">
            <label>Email Address</label>
            <input type="email" name="email" value="{{ email }}" required>
        </div>
        <div class="form-group">
            <label>New Password</label>
            <input type="password" name="new_password" placeholder="Leave blank to keep current">
        </div>
        <button type="submit" class="btn">🔒 Update Settings</button>
    </form>
</div>

<div class="security-note">
    <strong>🔒 Protected Against:</strong><br>
    • Cross-Site Request Forgery (CSRF)<br>
    • Session Hijacking via malicious sites<br>
    • Unauthorized account modifications
</div>
'''

LOGIN_CONTENT = '''
<div class="card">
    <h2>🔐 Secure Login</h2>
    {% if error %}
    <div class="alert alert-error">{{ error }}</div>
    {% endif %}
    <form method="POST" action="/login">
        <div class="form-group">
            <label>Username</label>
            <input type="text" name="username" required>
        </div>
        <div class="form-group">
            <label>Password</label>
            <input type="password" name="password" required>
        </div>
        <button type="submit" class="btn">Login</button>
    </form>
    <div class="security-note">
        <strong>📝 Test Credentials:</strong><br>
        alice:alice123 | bob:bob123 | charlie:charlie123
    </div>
</div>
'''

DASHBOARD_CONTENT = '''
<div class="card">
    <h2>💰 Account Balance</h2>
    <p class="balance">${{ "%.2f"|format(balance) }}</p>
</div>

<div class="card">
    <h2>📊 Quick Actions</h2>
    <a href="/transfer" class="btn" style="text-decoration:none; display:inline-block; margin-right:1rem;">🔒 Secure Transfer</a>
    <a href="/settings" class="btn" style="text-decoration:none; display:inline-block;">⚙️ Settings</a>
</div>

<div class="security-note">
    <strong>🛡️ Your Account is Protected</strong><br>
    This application implements industry-standard CSRF protections.
    Malicious websites cannot perform actions on your behalf.
</div>
'''


@app.route('/')
def index():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').lower()
        password = request.form.get('password', '')
        
        if username in users_db and users_db[username]['password'] == password:
            session['logged_in'] = True
            session['username'] = username
            # Generate new CSRF token on login
            session['csrf_token'] = secrets.token_hex(32)
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials'
    
    content = render_template_string(LOGIN_CONTENT, error=error, csrf_token=generate_csrf_token())
    return render_template_string(BASE_TEMPLATE, title='Login', content=content, session=session)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    username = session.get('username')
    balance = users_db[username]['balance']
    
    content = render_template_string(DASHBOARD_CONTENT, balance=balance)
    return render_template_string(BASE_TEMPLATE, title='Dashboard', content=content, session=session)


@app.route('/transfer', methods=['GET', 'POST'])
@csrf_protect  # CSRF Protection decorator!
def transfer():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    username = session.get('username')
    success = None
    error = None
    
    if request.method == 'POST':
        recipient = request.form.get('recipient', '').lower()
        try:
            amount = float(request.form.get('amount', 0))
        except ValueError:
            amount = 0
        
        if recipient not in users_db:
            error = 'Recipient not found'
        elif recipient == username:
            error = 'Cannot transfer to yourself'
        elif amount <= 0:
            error = 'Invalid amount'
        elif amount > users_db[username]['balance']:
            error = 'Insufficient funds'
        else:
            users_db[username]['balance'] -= amount
            users_db[recipient]['balance'] += amount
            
            transactions.append({
                'user': username,
                'type': 'SENT',
                'description': f'Transfer to {recipient}',
                'amount': amount
            })
            
            success = f'Successfully transferred ${amount:.2f} to {recipient}'
            print(f"[SECURE TRANSFER] {username} -> {recipient}: ${amount:.2f}")
            
            # Regenerate CSRF token after successful action (token rotation)
            session['csrf_token'] = secrets.token_hex(32)
    
    balance = users_db[username]['balance']
    users = list(users_db.keys())
    
    content = render_template_string(TRANSFER_CONTENT,
                                    balance=balance,
                                    users=users,
                                    current_user=username,
                                    success=success,
                                    error=error,
                                    csrf_token=generate_csrf_token())
    return render_template_string(BASE_TEMPLATE, title='Transfer', content=content, session=session)


@app.route('/settings', methods=['GET', 'POST'])
@csrf_protect
def settings():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    username = session.get('username')
    success = None
    
    if request.method == 'POST':
        new_email = request.form.get('email', '')
        new_password = request.form.get('new_password', '')
        
        if new_email:
            users_db[username]['email'] = new_email
        if new_password:
            users_db[username]['password'] = new_password
        
        success = 'Settings updated securely!'
        session['csrf_token'] = secrets.token_hex(32)
    
    email = users_db[username]['email']
    
    content = render_template_string(SETTINGS_CONTENT,
                                    email=email,
                                    success=success,
                                    csrf_token=generate_csrf_token())
    return render_template_string(BASE_TEMPLATE, title='Settings', content=content, session=session)


@app.errorhandler(403)
def forbidden(e):
    error_content = f'''
    <div class="card">
        <h2 style="color: #e74c3c;">🚫 Access Denied</h2>
        <p>{e.description}</p>
        <p style="margin-top: 1rem;">This request was blocked by CSRF protection.</p>
        <a href="/dashboard" class="btn">Return to Dashboard</a>
    </div>
    '''
    return render_template_string(BASE_TEMPLATE, title='Forbidden', content=error_content, session=session), 403


if __name__ == '__main__':
    print("=" * 60)
    print("CSRF PROTECTED BANK APPLICATION")
    print("=" * 60)
    print("🔒 Security Features Enabled:")
    print("   • CSRF Token validation")
    print("   • SameSite cookie attribute (Strict)")
    print("   • HTTPOnly cookie flag")
    print("   • Origin/Referer validation")
    print("   • Token rotation after actions")
    print("=" * 60)
    print("\n🌐 Starting SECURE server on http://127.0.0.1:5001")
    print("=" * 60)
    
    app.run(debug=True, host='127.0.0.1', port=5001)
