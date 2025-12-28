import http.server
import socketserver
import os
import sys

PORT = 8080
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class MyHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)
    
    def log_message(self, format, *args):
        print(f"[ATTACK SERVER] {args[0]}")

def main():
    print("=" * 60)
    print("          CSRF ATTACK SERVER")
    print("          For Educational Purposes Only!")
    print("=" * 60)
    print()
    print("This server hosts the malicious attack pages.")
    print()
    print("Available attack pages:")
    print(f"  • http://127.0.0.1:{PORT}/malicious_site.html")
    print(f"    (Interactive - requires button click)")
    print()
    print(f"  • http://127.0.0.1:{PORT}/auto_attack.html")
    print(f"    (Automatic - attacks on page load)")
    print()
    print("=" * 60)
    print()
    print("INSTRUCTIONS:")
    print("1. Start the vulnerable bank:  python vulnerable_bank.py")
    print("2. Login to the bank at:       http://127.0.0.1:5000")
    print("3. Open attack page in new tab (links above)")
    print("4. Check bank account - money is gone!")
    print()
    print("=" * 60)
    print(f"Starting attack server on http://127.0.0.1:{PORT}")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    
    with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[!] Server stopped")
            sys.exit(0)

if __name__ == "__main__":
    main()