
# CSRF Attack Proof of Concept

A comprehensive demonstration of Cross-Site Request Forgery (CSRF) attacks and defenses for educational purposes.

## Overview

This proof-of-concept demonstrates how CSRF attacks work by providing:
- A vulnerable banking application that lacks CSRF protection
- A secure banking application with proper defenses implemented
- Malicious attack pages that exploit the vulnerable application
- Automated scripts for attack demonstration and traffic analysis

## Project Structure

```
poc/
├── vulnerable_bank.py    # Bank app WITHOUT CSRF protection (port 5000)
├── secure_bank.py        # Bank app WITH CSRF protection (port 5001)
├── malicious_site.html   # Interactive attack page ("You Won!")
├── auto_attack.html      # Stealth auto-submit attack variant
├── attack_server.py      # Simple HTTP server for attack pages (port 8080)
├── csrf_attack_demo.py   # Automated Python attack script
├── traffic_capture.py    # PCAP generator for Wireshark analysis
├── requirements.txt      # Python dependencies
└── README.md            # This file
```

## Prerequisites

- Python 3.8 or higher
- pip package manager
- Modern web browser (Chrome, Firefox, Edge)
- Wireshark (optional, for traffic analysis)

## Installation

```bash
# Install required Python packages
pip install flask requests scapy

# Or using requirements.txt
pip install -r requirements.txt
```

## Running the Demonstration

### Step 1: Start the Vulnerable Bank (Terminal 1)

```bash
python vulnerable_bank.py
```

The vulnerable bank runs on http://127.0.0.1:5000

### Step 2: Start the Attack Server (Terminal 2)

```bash
python attack_server.py
```

The attack server runs on http://127.0.0.1:8080

### Step 3: (Optional) Start the Secure Bank (Terminal 3)

```bash
python secure_bank.py
```

The secure bank runs on http://127.0.0.1:5001

## Executing the Attack

### Manual Browser Attack

1. Open http://127.0.0.1:5000 in your browser
2. Login with credentials: `alice` / `alice123`
3. Note Alice's balance: **$10,000**
4. Open a new tab and navigate to http://127.0.0.1:8080/malicious_site.html
5. Click the "CLAIM NOW!" button
6. Return to the bank tab and refresh the page
7. Observe that Alice's balance is now **$9,500** - the attack succeeded!

### Auto-Submit Attack (Stealthier)

1. While logged in as alice, visit http://127.0.0.1:8080/auto_attack.html
2. The attack executes automatically on page load
3. The victim sees only "Session Expired" but the transfer already happened

### Automated Script Attack

```bash
python csrf_attack_demo.py
```

This script demonstrates the attack programmatically, showing:
- Login as victim
- Balance before attack
- CSRF attack execution
- Balance after attack

## Testing the Secure Application

1. Start the secure bank: `python secure_bank.py`
2. Login at http://127.0.0.1:5001
3. Attempt the same attack (modify attack pages to target port 5001)
4. The attack fails with HTTP 403 Forbidden - CSRF token validation blocked it

## Test Accounts

| Username | Password   | Initial Balance |
|----------|------------|-----------------|
| alice    | alice123   | $10,000         |
| bob      | bob123     | $5,000          |
| charlie  | charlie123 | $7,500          |

## Traffic Analysis with Wireshark

Generate PCAP files for network analysis:

```bash
# Generate sample packets
python traffic_capture.py --generate

# Open in Wireshark
wireshark csrf_attack.pcap
```

### Useful Wireshark Filters

- `http.referer contains "evil"` - Find requests from malicious sites
- `http.request.method == "POST"` - Filter POST requests
- `http contains "csrf_token"` - Find requests with CSRF tokens
- `tcp.port == 5000` - Filter traffic to vulnerable bank

## How the Attack Works

1. **Victim logs in** to the legitimate bank, receiving a session cookie
2. **Victim visits** attacker's page (via phishing link, compromised ad, etc.)
3. **Hidden form** on attacker's page targets the bank's transfer endpoint
4. **JavaScript submits** the form automatically (or on button click)
5. **Browser includes** session cookie with the request automatically
6. **Bank processes** what appears to be a legitimate authenticated request
7. **Money transferred** to attacker without victim's knowledge

## Defense Mechanisms Demonstrated

### In secure_bank.py:

1. **CSRF Tokens**: Random token in every form, validated on submission
2. **SameSite Cookies**: `SameSite=Strict` prevents cross-site cookie sending
3. **Origin Validation**: Checks Origin/Referer headers
4. **HTTPOnly Cookies**: Prevents JavaScript access to session cookie

## Key Differences: Vulnerable vs Secure

| Feature              | Vulnerable | Secure     |
|---------------------|------------|------------|
| CSRF Token          | No         | Yes        |
| SameSite Cookie     | No         | Strict     |
| Origin Validation   | No         | Yes        |
| HTTPOnly Cookie     | Default    | Yes        |
| Attack Result       | SUCCESS    | BLOCKED    |

## Security Notes

- Never deploy vulnerable_bank.py in any real environment
- The attack pages demonstrate real attack techniques
- Use only in isolated lab environments
- This project is for learning about web security

## Files Description

### vulnerable_bank.py
Flask application simulating a bank with user authentication, balance tracking, and fund transfers. Deliberately lacks CSRF protection to demonstrate the vulnerability.

### secure_bank.py
Same functionality as the vulnerable version, but with proper CSRF defenses:
- Synchronizer token pattern
- SameSite cookie configuration
- Origin header validation
- Token rotation after sensitive operations

### malicious_site.html
Fake "prize claim" page with hidden forms that execute CSRF attacks. Includes:
- Social engineering bait ("You Won!")
- Hidden form targeting bank's transfer endpoint
- Hidden iframe to prevent page navigation
- Attack status panel for demonstration

### auto_attack.html
Stealthier attack variant that auto-submits on page load. The victim only needs to visit the page - no click required.

### csrf_attack_demo.py
Python script demonstrating the attack programmatically using the requests library. Shows how attackers can automate CSRF exploitation.

### traffic_capture.py
Scapy-based tool for generating PCAP files containing example CSRF attack traffic. Useful for Wireshark analysis and understanding network-level indicators.

## References

- OWASP CSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- RFC 6265 (HTTP Cookies): https://tools.ietf.org/html/rfc6265
- SameSite Cookies: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite
