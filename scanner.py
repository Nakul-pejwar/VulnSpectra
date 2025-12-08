import requests
import socket
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup

class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.results = {
            "headers": [],
            "ports": [],
            "sqli": [],
            "xss": []
        }

    # 1. Check Security Headers
    def check_headers(self):
        try:
            response = requests.get(self.target_url)
            headers = response.headers
            missing_headers = []
            required_headers = [
                "X-Frame-Options",
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Content-Type-Options"
            ]
            
            for h in required_headers:
                if h not in headers:
                    missing_headers.append(f"Missing: {h}")
            
            if not missing_headers:
                self.results["headers"].append("All secure headers present.")
            else:
                self.results["headers"] = missing_headers
                
        except Exception as e:
            self.results["headers"].append(f"Error checking headers: {str(e)}")

    # 2. Check Open Ports (Basic Scan)
    def scan_ports(self):
        hostname = self.parsed_url.hostname
        # Common ports to scan (Web focused)
        ports = [80, 443, 8080, 8443, 21, 22]
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((hostname, port))
            if result == 0:
                self.results["ports"].append(f"Port {port} is OPEN")
            sock.close()

    # 3. SQL Injection (GET Parameters)
    def scan_sqli(self):
        # Load payloads
        with open('payloads/sqli.txt', 'r') as f:
            payloads = f.read().splitlines()

        params = parse_qs(self.parsed_url.query)
        if not params:
            return # No parameters to test

        for param in params.keys():
            for payload in payloads:
                # Construct malicious URL
                test_params = params.copy()
                test_params[param] = [payload]
                query_string = urlencode(test_params, doseq=True)
                test_url = self.parsed_url._replace(query=query_string)
                full_url = urlunparse(test_url)

                try:
                    res = requests.get(full_url)
                    # Simple error-based detection
                    if "syntax error" in res.text.lower() or "mysql" in res.text.lower():
                        self.results["sqli"].append(f"Vulnerable Param: {param} | Payload: {payload}")
                        break # Stop testing this param if vulnerable
                except:
                    pass

    # 4. XSS (Reflected)
    def scan_xss(self):
        with open('payloads/xss.txt', 'r') as f:
            payloads = f.read().splitlines()

        params = parse_qs(self.parsed_url.query)
        if not params:
            return

        for param in params.keys():
            for payload in payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                query_string = urlencode(test_params, doseq=True)
                test_url = self.parsed_url._replace(query=query_string)
                full_url = urlunparse(test_url)

                try:
                    res = requests.get(full_url)
                    if payload in res.text:
                        self.results["xss"].append(f"Reflected XSS: {param} | Payload: {payload}")
                        break
                except:
                    pass

    def run_scan(self):
        self.check_headers()
        self.scan_ports()
        self.scan_sqli()
        self.scan_xss()
        return self.results