#!/usr/bin/env python3
"""
CSRF Vulnerable Bank Application
================================
This is a deliberately vulnerable web application for educational purposes.
It demonstrates how CSRF attacks work by lacking proper CSRF protection.

DO NOT USE THIS CODE IN PRODUCTION!

Author: Security Protocols Course Assignment
Date: 2025
"""

from flask import Flask, request, session, redirect, url_for, render_template_string
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Simulated database of users and their balances
users_db = {
    'alice': {'password': 'alice123', 'balance': 10000.00, 'email': 'alice@example.com'},
    'bob': {'password': 'bob123', 'balance': 5000.00, 'email': 'bob@example.com'},
    'charlie': {'password': 'charlie123', 'balance': 7500.00, 'email': 'charlie@example.com'}
}

# Transaction history
transactions = []

# HTML Templates
BASE_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }} - VulnBank</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #fff;
        }
        .navbar {
            background: rgba(0,0,0,0.3);
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .navbar h1 {
            color: #e94560;
            font-size: 1.5rem;
        }
        .navbar a {
            color: #fff;
            text-decoration: none;
            margin-left: 1rem;
            padding: 0.5rem 1rem;
            border-radius: 5px;
            transition: background 0.3s;
        }
        .navbar a:hover {
            background: rgba(233, 69, 96, 0.3);
        }
        .container {
            max-width: 800px;
            margin: 2rem auto;
            padding: 2rem;
        }
        .card {
            background: rgba(255,255,255,0.1);
            border-radius: 15px;
            padding: 2rem;
            margin-bottom: 1.5rem;
            backdrop-filter: blur(10px);
        }
        .card h2 {
            color: #e94560;
            margin-bottom: 1rem;
        }
        .balance {
            font-size: 2.5rem;
            color: #4ecca3;
            font-weight: bold;
        }
        .form-group {
            margin-bottom: 1rem;
        }
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: #ccc;
        }
        .form-group input, .form-group select {
            width: 100%;
            padding: 0.75rem;
            border: none;
            border-radius: 8px;
            background: rgba(255,255,255,0.1);
            color: #fff;
            font-size: 1rem;
        }
        .form-group input:focus {
            outline: 2px solid #e94560;
        }
        .btn {
            background: #e94560;
            color: #fff;
            border: none;
            padding: 0.75rem 2rem;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1rem;
            transition: transform 0.2s, background 0.3s;
        }
        .btn:hover {
            background: #ff6b6b;
            transform: translateY(-2px);
        }
        .alert {
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1rem;
        }
        .alert-success {
            background: rgba(78, 204, 163, 0.3);
            border: 1px solid #4ecca3;
        }
        .alert-error {
            background: rgba(233, 69, 96, 0.3);
            border: 1px solid #e94560;
        }
        .transaction-list {
            list-style: none;
        }
        .transaction-list li {
            padding: 0.75rem;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            display: flex;
            justify-content: space-between;
        }
        .warning-banner {
            background: #ff6b6b;
            color: #fff;
            text-align: center;
            padding: 0.5rem;
            font-weight: bold;
        }
        .vulnerability-note {
            background: rgba(255, 193, 7, 0.2);
            border: 1px solid #ffc107;
            border-radius: 8px;
            padding: 1rem;
            margin-top: 1rem;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="warning-banner">⚠️ VULNERABLE APPLICATION - FOR EDUCATIONAL PURPOSES ONLY ⚠️</div>
    <nav class="navbar">
        <h1>🏦 VulnBank</h1>
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

LOGIN_CONTENT = '''
<div class="card">
    <h2>🔐 Login to VulnBank</h2>
    {% if error %}
    <div class="alert alert-error">{{ error }}</div>
    {% endif %}
    <form method="POST" action="/login">
        <div class="form-group">
            <label>Username</label>
            <input type="text" name="username" placeholder="Enter username" required>
        </div>
        <div class="form-group">
            <label>Password</label>
            <input type="password" name="password" placeholder="Enter password" required>
        </div>
        <button type="submit" class="btn">Login</button>
    </form>
    <div class="vulnerability-note">
        <strong>📝 Test Credentials:</strong><br>
        Username: alice | Password: alice123<br>
        Username: bob | Password: bob123
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
    <a href="/transfer" class="btn" style="text-decoration:none; display:inline-block; margin-right:1rem;">Transfer Money</a>
    <a href="/settings" class="btn" style="text-decoration:none; display:inline-block;">Account Settings</a>
</div>

<div class="card">
    <h2>📜 Recent Transactions</h2>
    {% if transactions %}
    <ul class="transaction-list">
        {% for t in transactions %}
        <li>
            <span>{{ t.type }}: {{ t.description }}</span>
            <span style="color: {{ '#4ecca3' if t.type == 'RECEIVED' else '#e94560' }}">${{ "%.2f"|format(t.amount) }}</span>
        </li>
        {% endfor %}
    </ul>
    {% else %}
    <p>No recent transactions</p>
    {% endif %}
</div>

<div class="vulnerability-note">
    <strong>🔓 CSRF Vulnerability:</strong> This application does not implement CSRF tokens. 
    The transfer form can be submitted from any external website without the user's knowledge.
</div>
'''

TRANSFER_CONTENT = '''
<div class="card">
    <h2>💸 Transfer Money</h2>
    {% if success %}
    <div class="alert alert-success">{{ success }}</div>
    {% endif %}
    {% if error %}
    <div class="alert alert-error">{{ error }}</div>
    {% endif %}
    
    <!-- VULNERABLE: No CSRF token protection! -->
    <form method="POST" action="/transfer">
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
            <input type="number" name="amount" min="0.01" step="0.01" placeholder="Enter amount" required>
        </div>
        <button type="submit" class="btn">Transfer</button>
    </form>
</div>

<div class="card">
    <h2>💳 Your Current Balance</h2>
    <p class="balance">${{ "%.2f"|format(balance) }}</p>
</div>

<div class="vulnerability-note">
    <strong>🔓 Vulnerability Details:</strong><br>
    • No CSRF token in the form<br>
    • Form accepts POST requests from any origin<br>
    • No SameSite cookie attribute<br>
    • No Referer header validation
</div>
'''

SETTINGS_CONTENT = '''
<div class="card">
    <h2>⚙️ Account Settings</h2>
    {% if success %}
    <div class="alert alert-success">{{ success }}</div>
    {% endif %}
    {% if error %}
    <div class="alert alert-error">{{ error }}</div>
    {% endif %}
    
    <!-- VULNERABLE: No CSRF token protection! -->
    <form method="POST" action="/settings">
        <div class="form-group">
            <label>Email Address</label>
            <input type="email" name="email" value="{{ email }}" required>
        </div>
        <div class="form-group">
            <label>New Password (leave blank to keep current)</label>
            <input type="password" name="new_password" placeholder="New password">
        </div>
        <button type="submit" class="btn">Update Settings</button>
    </form>
</div>

<div class="vulnerability-note">
    <strong>🔓 Vulnerability:</strong> An attacker can change your email/password via CSRF, 
    potentially locking you out of your account!
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
            # VULNERABLE: Cookie without SameSite attribute
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username or password'
    
    content = render_template_string(LOGIN_CONTENT, error=error)
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
    
    # Get user's transactions
    user_transactions = [t for t in transactions if t['user'] == username][-5:]
    
    content = render_template_string(DASHBOARD_CONTENT, 
                                    balance=balance, 
                                    transactions=user_transactions)
    return render_template_string(BASE_TEMPLATE, title='Dashboard', content=content, session=session)


@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    """
    VULNERABLE ENDPOINT - No CSRF Protection!
    
    This endpoint processes money transfers without validating:
    1. CSRF tokens
    2. Origin/Referer headers
    3. Custom headers
    
    An attacker can craft a malicious page that submits a form to this endpoint,
    and if the victim visits that page while logged in, the transfer will execute.
    """
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
        
        # Validate transfer
        if recipient not in users_db:
            error = 'Recipient not found'
        elif recipient == username:
            error = 'Cannot transfer to yourself'
        elif amount <= 0:
            error = 'Invalid amount'
        elif amount > users_db[username]['balance']:
            error = 'Insufficient funds'
        else:
            # Process transfer (NO CSRF VALIDATION!)
            users_db[username]['balance'] -= amount
            users_db[recipient]['balance'] += amount
            
            # Log transactions
            transactions.append({
                'user': username,
                'type': 'SENT',
                'description': f'Transfer to {recipient}',
                'amount': amount
            })
            transactions.append({
                'user': recipient,
                'type': 'RECEIVED',
                'description': f'Transfer from {username}',
                'amount': amount
            })
            
            success = f'Successfully transferred ${amount:.2f} to {recipient}'
            print(f"[TRANSFER] {username} -> {recipient}: ${amount:.2f}")
    
    balance = users_db[username]['balance']
    users = list(users_db.keys())
    
    content = render_template_string(TRANSFER_CONTENT,
                                    balance=balance,
                                    users=users,
                                    current_user=username,
                                    success=success,
                                    error=error)
    return render_template_string(BASE_TEMPLATE, title='Transfer', content=content, session=session)


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    """
    VULNERABLE ENDPOINT - No CSRF Protection!
    
    This endpoint allows changing email and password without CSRF validation.
    An attacker could change the victim's email to their own, then use
    password reset functionality to take over the account.
    """
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    username = session.get('username')
    success = None
    error = None
    
    if request.method == 'POST':
        new_email = request.form.get('email', '')
        new_password = request.form.get('new_password', '')
        
        if new_email:
            users_db[username]['email'] = new_email
            success = 'Settings updated successfully!'
            print(f"[SETTINGS] {username} email changed to: {new_email}")
        
        if new_password:
            users_db[username]['password'] = new_password
            success = 'Settings updated successfully!'
            print(f"[SETTINGS] {username} password changed")
    
    email = users_db[username]['email']
    
    content = render_template_string(SETTINGS_CONTENT,
                                    email=email,
                                    success=success,
                                    error=error)
    return render_template_string(BASE_TEMPLATE, title='Settings', content=content, session=session)


@app.route('/api/balance')
def api_balance():
    """API endpoint to check balance (for demonstration)"""
    if not session.get('logged_in'):
        return {'error': 'Not authenticated'}, 401
    
    username = session.get('username')
    return {
        'username': username,
        'balance': users_db[username]['balance'],
        'email': users_db[username]['email']
    }


if __name__ == '__main__':
    print("=" * 60)
    print("CSRF VULNERABLE BANK APPLICATION")
    print("=" * 60)
    print("⚠️  WARNING: This is an intentionally vulnerable application!")
    print("⚠️  DO NOT use in production or expose to the internet!")
    print("=" * 60)
    print("\n📝 Test Credentials:")
    print("   alice:alice123 (Balance: $10,000)")
    print("   bob:bob123 (Balance: $5,000)")
    print("   charlie:charlie123 (Balance: $7,500)")
    print("\n🌐 Starting server on http://127.0.0.1:5000")
    print("=" * 60)
    
    app.run(debug=True, host='127.0.0.1', port=5000)
