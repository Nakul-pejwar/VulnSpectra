import requests
import socket
from bs4 import BeautifulSoup, Tag
from urllib.parse import urljoin
from typing import Optional, List, Dict, Any
import argparse

class VulnerabilityScanner:
    def __init__(self, target_url: str, session: Optional[requests.Session] = None):
        self.target_url: str = target_url
        self.session: requests.Session = session or requests.Session()

    def run_scan(self) -> Dict[str, List[str]]:
        """
        Runs all checks and returns a DICTIONARY of findings.
        """
        print(f"[*] Starting scan on {self.target_url}...")
        
        # We collect results in a structured dictionary
        # This matches what your index.html expects
        scan_results: Dict[str, List[str]] = {
            "headers": self.check_security_headers(self.target_url),
            "sql": self.scan_sql_injection(self.target_url),
            "xss": self.scan_xss(self.target_url),
            "ports": self.scan_ports(self.target_url)
        }
        
        return scan_results

    def extract_forms(self, url: str) -> List[Tag]:
        try:
            response: requests.Response = self.session.get(url)
            soup: BeautifulSoup = BeautifulSoup(response.content, "html.parser")
            return soup.find_all("form")
        except requests.exceptions.RequestException:
            return []

    def submit_form(self, form: Tag, value: str, url: str) -> requests.Response:
        action: str = str(form.get("action")) # Force string to fix type error
        post_url: str = urljoin(url, action)
        method: str = str(form.get("method")) # Force string to fix type error

        inputs_list: List[Tag] = form.find_all("input")
        post_data: Dict[str, Any] = {}
        
        for input_tag in inputs_list:
            input_name: Optional[str] = input_tag.get("name") # type: ignore
            input_type: Optional[str] = input_tag.get("type") # type: ignore
            input_val: Optional[str] = input_tag.get("value") # type: ignore
            
            if input_type == "text":
                if input_name:
                    post_data[input_name] = value
            elif input_name:
                post_data[input_name] = input_val
        
        if method.lower() == "post":
            return self.session.post(post_url, data=post_data)
        return self.session.get(post_url, params=post_data)

    def scan_sql_injection(self, url: str) -> List[str]:
        findings: List[str] = []  # Explicit type hint fixes "append" error
        sql_payloads: List[str] = ["'", "\"", "' OR '1'='1"]
        forms: List[Tag] = self.extract_forms(url)
        
        print(f"[+] Scanning {len(forms)} forms for SQL Injection...")
        for form in forms:
            for payload in sql_payloads:
                try:
                    response = self.submit_form(form, payload, url)
                    if "You have an error in your SQL syntax" in response.text or \
                       "mysql_fetch" in response.text:
                        
                        # Convert to string to satisfy strict mode
                        action = str(form.get('action'))
                        msg = f"Vulnerability in form action: {action} with payload: {payload}"
                        if msg not in findings:
                            findings.append(msg)
                except:
                    continue
        return findings

    def scan_xss(self, url: str) -> List[str]:
        findings: List[str] = [] # Explicit type hint fixes "append" error
        xss_payload: str = "<script>alert('XSS')</script>"
        forms: List[Tag] = self.extract_forms(url)
        
        print(f"[+] Scanning {len(forms)} forms for XSS...")
        for form in forms:
            try:
                response = self.submit_form(form, xss_payload, url)
                if xss_payload in response.content.decode():
                    action = str(form.get('action'))
                    msg = f"XSS found in form action: {action}"
                    if msg not in findings:
                        findings.append(msg)
            except:
                continue
        return findings

    def check_security_headers(self, url: str) -> List[str]:
        findings: List[str] = []
        try:
            response = self.session.get(url)
            headers = response.headers
            required_headers = ["X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy"]
            
            for header in required_headers:
                if header not in headers:
                    findings.append(f"Missing Header: {header}")
        except:
            findings.append("Could not fetch headers (Connection Error)")
        return findings

    def scan_ports(self, url: str) -> List[str]:
        findings: List[str] = []
        # Extract hostname safely
        hostname = url.replace("http://", "").replace("https://", "").split("/")[0]
        ports = [21, 22, 80, 443, 3306]
        
        print(f"[+] Scanning ports for {hostname}...")
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((hostname, port))
                if result == 0:
                    findings.append(f"Port {port} is OPEN")
                sock.close()
            except:
                pass
        return findings

# CLI Execution
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnSpectra CLI")
    parser.add_argument("url", help="Target URL")
    args = parser.parse_args()

    scanner = VulnerabilityScanner(args.url)
    results = scanner.run_scan()

    print("\n" + "="*40)
    print(" SCAN REPORT")
    print("="*40)
    
    # Iterate through the dictionary keys to print results
    for category, findings in results.items():
        if findings:
            print(f"\n[{category.upper()}] Found {len(findings)} issues:")
            for issue in findings:
                print(f" - {issue}")
    
    print("\n" + "="*40 + "\n")