# CSRF Attack Proof of Concept

## Overview

This Proof of Concept (PoC) demonstrates Cross-Site Request Forgery (CSRF) attacks against web applications. It includes both a vulnerable application and a protected application to showcase the importance of CSRF defenses.

> ⚠️ **WARNING**: This code is for educational purposes only. Do not use these techniques against systems you do not own or have permission to test.

## Project Structure

```
poc/
├── vulnerable_bank.py      # Vulnerable Flask application (NO CSRF protection)
├── secure_bank.py          # Protected Flask application (WITH CSRF protection)
├── malicious_site.html     # Attacker's malicious webpage
├── csrf_attack_demo.py     # Automated attack demonstration script
├── traffic_analyzer.py     # Network traffic analyzer for CSRF detection
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the Vulnerable Application

```bash
python vulnerable_bank.py
```

This starts the vulnerable bank on `http://127.0.0.1:5000`

**Test Credentials:**
- alice:alice123 (Balance: $10,000)
- bob:bob123 (Balance: $5,000)
- charlie:charlie123 (Balance: $7,500)

### 3. Execute CSRF Attack

**Method A: Using the Malicious Website**

1. Open a browser and login to the vulnerable bank at `http://127.0.0.1:5000`
2. Open `malicious_site.html` in another tab
3. Click "CLAIM NOW!" button
4. Return to the bank - your money has been transferred!

**Method B: Using the Attack Script**

```bash
python csrf_attack_demo.py
```

### 4. Compare with Protected Application

```bash
python secure_bank.py
```

This starts the secure bank on `http://127.0.0.1:5001`

Try the same attack - it will be blocked!

## Attack Demonstration

### What the Attack Does

1. **Transfer Attack**: Transfers $500 from victim (alice) to attacker (bob)
2. **Email Change Attack**: Changes victim's email to `attacker@evil.com`

### How It Works

```
Victim                    Attacker's Site               Vulnerable Bank
  │                            │                              │
  │ ──visits────────────────►  │                              │
  │                            │                              │
  │    (hidden form auto-submits)                             │
  │                            │ ──POST /transfer─────────►   │
  │                            │    (with victim's cookies)   │
  │                            │                              │
  │                            │   ◄────── 200 OK ───────────│
  │                            │                              │
  │   ◄── "You won a prize!"   │                              │
  │                            │         (money stolen!)      │
```

## Files Description

### vulnerable_bank.py

A deliberately insecure banking application that lacks:
- CSRF token validation
- SameSite cookie attribute
- Origin/Referer header checks

### secure_bank.py

A properly protected application implementing:
- **CSRF Tokens**: Unique tokens in each form, validated on submission
- **SameSite Cookies**: `SameSite=Strict` prevents cross-origin cookie sending
- **Origin Validation**: Checks that requests come from allowed origins
- **Token Rotation**: New token generated after sensitive actions

### malicious_site.html

A fake "prize winning" page that contains hidden forms targeting the vulnerable bank. Demonstrates how attackers can social engineer victims into triggering CSRF attacks.

### csrf_attack_demo.py

Python script that programmatically demonstrates:
- Establishing a session as the victim
- Checking initial balance
- Executing CSRF attacks
- Verifying the attack results
- Comparing vulnerable vs. protected applications

### traffic_analyzer.py

Network analysis tool that:
- Captures HTTP traffic using Scapy
- Analyzes requests for CSRF indicators
- Identifies suspicious cross-origin requests
- Reports missing security headers

Usage:
```bash
# Demo mode (no packet capture)
python traffic_analyzer.py --demo

# Live capture (requires root)
sudo python traffic_analyzer.py --capture -i lo
```

## Security Measures Implemented (Secure Version)

| Protection | Description |
|------------|-------------|
| CSRF Tokens | Cryptographically random tokens tied to user session |
| SameSite=Strict | Cookie not sent on cross-origin requests |
| HTTPOnly | Cookie not accessible via JavaScript |
| Origin Validation | Server checks Origin/Referer headers |
| Token Rotation | New token after each sensitive action |

## Testing Checklist

- [ ] Vulnerable app allows cross-origin POST requests
- [ ] Vulnerable app processes requests without CSRF tokens
- [ ] Malicious site can transfer money when victim is logged in
- [ ] Secure app blocks requests without valid CSRF token
- [ ] Secure app blocks requests from different origins
- [ ] Attack script demonstrates both success and failure cases

## Educational Notes

### Why CSRF Works

1. **Cookies are automatic**: Browsers include cookies for a domain regardless of where the request originates
2. **Trust in session**: Applications that only check session cookies trust any request with valid cookies
3. **Predictable requests**: If attackers know the request format, they can forge it

### Defense Strategies

1. **Synchronizer Token Pattern**: Include unpredictable token in requests
2. **SameSite Cookies**: Modern defense preventing cross-site cookie transmission
3. **Double Submit Cookie**: Token in both cookie and request body
4. **Custom Headers**: Require headers that simple forms can't set (X-Requested-With)
5. **Origin Checking**: Validate Origin/Referer headers

## References

- OWASP CSRF Prevention Cheat Sheet
- RFC 6265 (HTTP State Management - Cookies)
- Same-Origin Policy (SOP)
- SameSite Cookie Attribute

## License

This project is for educational purposes only. Use responsibly and ethically.
