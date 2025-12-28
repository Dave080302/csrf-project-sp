#!/usr/bin/env python3
"""
CSRF Traffic Capture & PCAP Generator
======================================
This tool captures HTTP traffic and generates PCAP files that can be
analyzed in Wireshark.

Features:
1. Generate sample PCAP files showing CSRF attacks
2. Capture live traffic (requires admin/root)
3. Analyze existing PCAP files for CSRF indicators

Requirements:
    pip install scapy

Usage:
    python traffic_capture.py --generate          # Generate sample PCAP files
    python traffic_capture.py --analyze file.pcap # Analyze existing PCAP
    sudo python traffic_capture.py --capture      # Live capture (requires root)

FOR EDUCATIONAL PURPOSES ONLY!
"""

import argparse
import os
import sys
from datetime import datetime
import platform

# Try to import scapy
try:
    from scapy.all import (
        Ether, IP, TCP, Raw, 
        wrpcap, rdpcap, sniff,
        conf, get_if_list
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not installed. Install with: pip install scapy")


class CSRFPacketGenerator:
    """Generates sample PCAP files demonstrating CSRF attacks."""
    
    def __init__(self):
        self.src_ip = "192.168.1.100"  # Victim's IP
        self.dst_ip = "192.168.1.1"    # Bank server IP
        self.src_port = 54321
        self.dst_port = 5000
        self.seq = 1000
        self.ack = 2000
        
    def create_http_request(self, method, path, headers, body=""):
        """Create an HTTP request packet."""
        http_data = f"{method} {path} HTTP/1.1\r\n"
        for key, value in headers.items():
            http_data += f"{key}: {value}\r\n"
        http_data += f"Content-Length: {len(body)}\r\n"
        http_data += "\r\n"
        http_data += body
        
        packet = (
            Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") /
            IP(src=self.src_ip, dst=self.dst_ip) /
            TCP(sport=self.src_port, dport=self.dst_port, 
                flags="PA", seq=self.seq, ack=self.ack) /
            Raw(load=http_data.encode())
        )
        
        self.seq += len(http_data)
        self.src_port += 1
        
        return packet
    
    def create_http_response(self, status_code, status_text, body=""):
        """Create an HTTP response packet."""
        http_data = f"HTTP/1.1 {status_code} {status_text}\r\n"
        http_data += "Content-Type: text/html\r\n"
        http_data += f"Content-Length: {len(body)}\r\n"
        http_data += "\r\n"
        http_data += body
        
        packet = (
            Ether(src="11:22:33:44:55:66", dst="aa:bb:cc:dd:ee:ff") /
            IP(src=self.dst_ip, dst=self.src_ip) /
            TCP(sport=self.dst_port, dport=self.src_port - 1,
                flags="PA", seq=self.ack, ack=self.seq) /
            Raw(load=http_data.encode())
        )
        
        return packet
    
    def generate_legitimate_request(self):
        """Generate a legitimate request with CSRF token."""
        headers = {
            "Host": "127.0.0.1:5000",
            "Origin": "http://127.0.0.1:5000",
            "Referer": "http://127.0.0.1:5000/transfer",
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": "session=abc123def456",
            "X-Requested-With": "XMLHttpRequest",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
        }
        body = "csrf_token=a1b2c3d4e5f6g7h8&recipient=bob&amount=100"
        
        return self.create_http_request("POST", "/transfer", headers, body)
    
    def generate_csrf_attack_request(self):
        """Generate a CSRF attack request (no token, external origin)."""
        headers = {
            "Host": "127.0.0.1:5000",
            "Origin": "http://evil-attacker-site.com",
            "Referer": "http://evil-attacker-site.com/malicious.html",
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": "session=abc123def456",  # Victim's cookie is still sent!
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
        }
        body = "recipient=attacker&amount=1000"  # No CSRF token!
        
        return self.create_http_request("POST", "/transfer", headers, body)
    
    def generate_csrf_no_headers_request(self):
        """Generate a CSRF attack with missing headers."""
        headers = {
            "Host": "127.0.0.1:5000",
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": "session=abc123def456",
            "User-Agent": "Mozilla/5.0"
            # Missing: Origin, Referer
        }
        body = "email=hacker@evil.com&new_password=pwned123"
        
        return self.create_http_request("POST", "/settings", headers, body)
    
    def generate_login_request(self):
        """Generate a login request."""
        headers = {
            "Host": "127.0.0.1:5000",
            "Origin": "http://127.0.0.1:5000",
            "Referer": "http://127.0.0.1:5000/login",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
        }
        body = "username=alice&password=alice123"
        
        return self.create_http_request("POST", "/login", headers, body)
    
    def generate_sample_pcaps(self, output_dir="."):
        """Generate sample PCAP files for analysis."""
        os.makedirs(output_dir, exist_ok=True)
        
        files_created = []
        
        # 1. Legitimate traffic
        print("[*] Generating legitimate_traffic.pcap...")
        packets = [
            self.generate_login_request(),
            self.create_http_response(302, "Found", "Redirecting to /dashboard"),
            self.generate_legitimate_request(),
            self.create_http_response(200, "OK", "Transfer successful")
        ]
        filename = os.path.join(output_dir, "legitimate_traffic.pcap")
        wrpcap(filename, packets)
        files_created.append(filename)
        print(f"    Created: {filename}")
        
        # Reset sequence numbers
        self.seq = 1000
        self.ack = 2000
        self.src_port = 54321
        
        # 2. CSRF attack traffic
        print("[*] Generating csrf_attack.pcap...")
        packets = [
            self.generate_csrf_attack_request(),
            self.create_http_response(200, "OK", "Transfer successful - $1000 sent!")
        ]
        filename = os.path.join(output_dir, "csrf_attack.pcap")
        wrpcap(filename, packets)
        files_created.append(filename)
        print(f"    Created: {filename}")
        
        # Reset
        self.seq = 1000
        self.ack = 2000
        self.src_port = 54321
        
        # 3. CSRF with missing headers
        print("[*] Generating csrf_missing_headers.pcap...")
        packets = [
            self.generate_csrf_no_headers_request(),
            self.create_http_response(200, "OK", "Settings updated")
        ]
        filename = os.path.join(output_dir, "csrf_missing_headers.pcap")
        wrpcap(filename, packets)
        files_created.append(filename)
        print(f"    Created: {filename}")
        
        # Reset
        self.seq = 1000
        self.ack = 2000
        self.src_port = 54321
        
        # 4. Complete attack scenario
        print("[*] Generating complete_attack_scenario.pcap...")
        packets = [
            # Victim logs in normally
            self.generate_login_request(),
            self.create_http_response(302, "Found"),
            # Victim does legitimate transfer
            self.generate_legitimate_request(),
            self.create_http_response(200, "OK"),
            # CSRF ATTACK HAPPENS
            self.generate_csrf_attack_request(),
            self.create_http_response(200, "OK", "Transfer successful"),
            # Another CSRF attack - email change
            self.generate_csrf_no_headers_request(),
            self.create_http_response(200, "OK")
        ]
        filename = os.path.join(output_dir, "complete_attack_scenario.pcap")
        wrpcap(filename, packets)
        files_created.append(filename)
        print(f"    Created: {filename}")
        
        return files_created


class CSRFPacketAnalyzer:
    """Analyzes PCAP files for CSRF attack indicators."""
    
    def __init__(self):
        self.indicators = {
            'external_origin': [],
            'external_referer': [],
            'missing_csrf_token': [],
            'missing_origin': [],
            'missing_referer': [],
            'suspicious_keywords': []
        }
    
    def analyze_pcap(self, filename):
        """Analyze a PCAP file for CSRF indicators."""
        print(f"\n{'='*70}")
        print(f"ANALYZING: {filename}")
        print(f"{'='*70}\n")
        
        try:
            packets = rdpcap(filename)
        except Exception as e:
            print(f"Error reading PCAP: {e}")
            return
        
        http_requests = []
        
        for pkt in packets:
            if pkt.haslayer(Raw):
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                    if payload.startswith(('GET', 'POST', 'PUT', 'DELETE')):
                        http_requests.append(payload)
                except:
                    continue
        
        print(f"Found {len(http_requests)} HTTP requests\n")
        
        for i, req in enumerate(http_requests, 1):
            print(f"--- Request #{i} ---")
            self.analyze_request(req)
            print()
    
    def analyze_request(self, raw_request):
        """Analyze a single HTTP request for CSRF indicators."""
        lines = raw_request.split('\r\n')
        
        # Parse request line
        request_line = lines[0].split(' ')
        method = request_line[0]
        path = request_line[1] if len(request_line) > 1 else '/'
        
        print(f"Method: {method}")
        print(f"Path: {path}")
        
        # Parse headers
        headers = {}
        body = ""
        in_body = False
        
        for line in lines[1:]:
            if line == '':
                in_body = True
                continue
            if in_body:
                body += line
            else:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
        
        # Check for CSRF indicators
        findings = []
        
        # Only analyze POST/PUT/DELETE requests
        if method not in ['POST', 'PUT', 'DELETE', 'PATCH']:
            print("Status: GET request - not typically vulnerable to CSRF")
            return
        
        # Check Origin header
        origin = headers.get('origin', '')
        if not origin:
            findings.append(("[HIGH] Missing Origin header", 'missing_origin'))
        elif '127.0.0.1' not in origin and 'localhost' not in origin:
            findings.append((f"[CRITICAL] External Origin: {origin}", 'external_origin'))
        
        # Check Referer header
        referer = headers.get('referer', '')
        if not referer:
            findings.append(("[MEDIUM] Missing Referer header", 'missing_referer'))
        elif '127.0.0.1' not in referer and 'localhost' not in referer:
            findings.append((f"[HIGH] External Referer: {referer}", 'external_referer'))
        
        # Check for CSRF token in body
        csrf_patterns = ['csrf_token', 'csrf', '_token', 'authenticity_token']
        has_token = any(p in body.lower() for p in csrf_patterns)
        if not has_token:
            findings.append(("[HIGH] No CSRF token in request body", 'missing_csrf_token'))
        
        # Check for suspicious keywords
        suspicious = ['evil', 'attacker', 'malicious', 'hack']
        for keyword in suspicious:
            if keyword in body.lower() or keyword in referer.lower() or keyword in origin.lower():
                findings.append((f"[CRITICAL] Suspicious keyword: {keyword}", 'suspicious_keywords'))
        
        # Print analysis
        print(f"Origin: {origin or 'NOT PRESENT'}")
        print(f"Referer: {referer or 'NOT PRESENT'}")
        print(f"Cookie: {headers.get('cookie', 'NOT PRESENT')[:50]}...")
        print(f"Body preview: {body[:100]}...")
        
        if findings:
            print("\n⚠️  POTENTIAL CSRF ATTACK DETECTED!")
            print("Indicators:")
            for finding, category in findings:
                print(f"  • {finding}")
                self.indicators[category].append(finding)
        else:
            print("\n✓ Request appears legitimate")


def live_capture(interface, ports, count, output_file):
    """Capture live traffic and save to PCAP."""
    print(f"\n{'='*60}")
    print("LIVE TRAFFIC CAPTURE")
    print(f"{'='*60}")
    print(f"Interface: {interface}")
    print(f"Ports: {ports}")
    print(f"Output: {output_file}")
    print(f"Packet limit: {'Unlimited' if count == 0 else count}")
    print("\nCapturing... Press Ctrl+C to stop\n")
    
    # Build BPF filter
    port_filter = ' or '.join([f'port {p}' for p in ports])
    bpf_filter = f'tcp and ({port_filter})'
    
    # Validate interface exists (when scapy is available)
    try:
        if SCAPY_AVAILABLE:
            try:
                available = get_if_list()
            except Exception:
                available = []
            if available and interface not in available:
                print(f"Error: Interface '{interface}' not found.")
                print("Available interfaces:")
                for i in available:
                    print(f"  - {i}")
                print("Specify a valid interface with -i or run: python traffic_capture.py --help")
                return

        packets = sniff(
            iface=interface,
            filter=bpf_filter,
            count=count if count > 0 else 0,
            store=True
        )
        
        print(f"\nCaptured {len(packets)} packets")
        
        if packets:
            wrpcap(output_file, packets)
            print(f"Saved to: {output_file}")
            print(f"\nOpen in Wireshark: wireshark {output_file}")
        
    except PermissionError:
        print("Error: Permission denied. Run with sudo/administrator privileges.")
    except Exception as e:
        print(f"Error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='CSRF Traffic Capture & PCAP Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python traffic_capture.py --generate                    # Generate sample PCAPs
  python traffic_capture.py --generate -o ./pcaps        # Generate to specific directory
  python traffic_capture.py --analyze csrf_attack.pcap   # Analyze a PCAP file
  sudo python traffic_capture.py --capture -o live.pcap  # Live capture
        '''
    )
    
    parser.add_argument('--generate', action='store_true',
                       help='Generate sample PCAP files demonstrating CSRF attacks')
    parser.add_argument('--analyze', type=str, metavar='FILE',
                       help='Analyze an existing PCAP file for CSRF indicators')
    parser.add_argument('--capture', action='store_true',
                       help='Capture live traffic (requires root/admin)')
    parser.add_argument('-o', '--output', type=str, default='.',
                       help='Output directory for generated files or filename for capture')
    # Choose a sensible default interface depending on platform and available interfaces
    default_iface = 'lo'
    if SCAPY_AVAILABLE:
        try:
            if_list = get_if_list()
        except Exception:
            if_list = []

        if platform.system().lower().startswith('win'):
            # Try to select a loopback or Npcap loopback adapter on Windows
            candidates = [i for i in if_list if 'loop' in i.lower() or 'npcap' in i.lower() or 'npf' in i.lower()]
            default_iface = candidates[0] if candidates else (if_list[0] if if_list else 'lo')
        else:
            # Use 'lo' on Unix-like systems if present, else first interface
            default_iface = 'lo' if 'lo' in if_list else (if_list[0] if if_list else 'lo')

    parser.add_argument('-i', '--interface', type=str, default=default_iface,
                       help=f'Network interface for live capture (default: {default_iface})')
    parser.add_argument('-p', '--ports', nargs='+', type=int, default=[5000, 5001],
                       help='Ports to monitor (default: 5000 5001)')
    parser.add_argument('-c', '--count', type=int, default=100,
                       help='Number of packets to capture (0=unlimited, default: 100)')
    
    args = parser.parse_args()
    
    if not SCAPY_AVAILABLE:
        print("Error: Scapy is required but not installed.")
        print("Install it with: pip install scapy")
        print("\nOn Windows, you may also need Npcap: https://npcap.com/")
        sys.exit(1)

    # If user requested live capture but scapy has no pcap provider, show actionable message
    if args.capture and SCAPY_AVAILABLE and not getattr(conf, 'use_pcap', False):
        print("Error: No libpcap provider available. Scapy cannot capture packets on this system.")
        print("On Windows install Npcap (https://npcap.com/) and enable the 'Support loopback traffic' option.")
        print("After installing, reboot and try again.")
        sys.exit(1)
    
    if args.generate:
        print("\n" + "="*60)
        print("GENERATING SAMPLE PCAP FILES")
        print("="*60 + "\n")
        
        generator = CSRFPacketGenerator()
        files = generator.generate_sample_pcaps(args.output)
        
        print("\n" + "="*60)
        print("GENERATION COMPLETE")
        print("="*60)
        print(f"\nCreated {len(files)} PCAP files:")
        for f in files:
            print(f"  • {f}")
        print("\nOpen in Wireshark to analyze:")
        print(f"  wireshark {files[0]}")
        print("\nIn Wireshark, use these filters:")
        print("  • http.request.method == POST")
        print("  • http.referer contains \"evil\"")
        print("  • http.cookie contains \"session\"")
        
    elif args.analyze:
        if not os.path.exists(args.analyze):
            print(f"Error: File not found: {args.analyze}")
            sys.exit(1)
        
        analyzer = CSRFPacketAnalyzer()
        analyzer.analyze_pcap(args.analyze)
        
        print("\n" + "="*60)
        print("ANALYSIS SUMMARY")
        print("="*60)
        total = sum(len(v) for v in analyzer.indicators.values())
        if total > 0:
            print(f"\n⚠️  Found {total} CSRF indicators:")
            for category, items in analyzer.indicators.items():
                if items:
                    print(f"\n{category.replace('_', ' ').title()}: {len(items)}")
                    for item in items:
                        print(f"  • {item}")
        else:
            print("\n✓ No CSRF indicators found in traffic")
        
    elif args.capture:
        output = args.output if args.output.endswith('.pcap') else os.path.join(args.output, 'capture.pcap')
        live_capture(args.interface, args.ports, args.count, output)
        
    else:
        parser.print_help()
        print("\n" + "="*60)
        print("QUICK START")
        print("="*60)
        print("\n1. Generate sample PCAP files:")
        print("   python traffic_capture.py --generate")
        print("\n2. Open in Wireshark:")
        print("   wireshark csrf_attack.pcap")


if __name__ == '__main__':
    main()