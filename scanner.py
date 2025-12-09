import requests
import socket
from bs4 import BeautifulSoup, Tag
from urllib.parse import urljoin
from typing import Optional, List, Dict, Any
import argparse
import time

class VulnerabilityScanner:
    def __init__(self, target_url: str, session: Optional[requests.Session] = None):
        self.target_url: str = target_url
        self.session: requests.Session = session or requests.Session()

    def extract_forms(self, url: str) -> List[Tag]:
        try:
            response: requests.Response = self.session.get(url, timeout=10)
            soup: BeautifulSoup = BeautifulSoup(response.content, "html.parser")
            return soup.find_all("form")
        except requests.exceptions.RequestException:
            return []

    def submit_form(self, form: Tag, value: str, url: str) -> requests.Response:
        action: str = str(form.get("action"))
        post_url: str = urljoin(url, action)
        method: str = str(form.get("method"))

        inputs_list: List[Tag] = form.find_all("input")
        post_data: Dict[str, Any] = {}
        
        for input_tag in inputs_list:
            input_name: Optional[str] = input_tag.get("name") # type: ignore
            input_type: Optional[str] = input_tag.get("type") # type: ignore
            input_val: Optional[str] = input_tag.get("value") # type: ignore
            
            # Inject payload into all text fields
            if input_type == "text":
                if input_name:
                    post_data[input_name] = value
            elif input_name:
                post_data[input_name] = input_val
        
        if method.lower() == "post":
            return self.session.post(post_url, data=post_data, timeout=10)
        return self.session.get(post_url, params=post_data, timeout=10)

    # --- Step 1: Headers ---
    def check_security_headers(self) -> List[str]:
        findings: List[str] = []
        try:
            response = self.session.get(self.target_url, timeout=5)
            headers = response.headers
            required_headers = ["X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy"]
            
            for header in required_headers:
                if header not in headers:
                    findings.append(f"Missing Header: {header}")
        except:
            findings.append("Could not fetch headers (Connection Error)")
        return findings

    # --- Step 2: Ports ---
    def scan_ports(self) -> List[str]:
        findings: List[str] = []
        hostname = self.target_url.replace("http://", "").replace("https://", "").split("/")[0]
        ports = [21, 22, 80, 443, 3306]
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5) 
                result = sock.connect_ex((hostname, port))
                if result == 0:
                    findings.append(f"Port {port} is OPEN")
                sock.close()
            except:
                pass
        return findings

    # --- Step 3: SQL Injection ---
    def scan_sql_injection(self) -> List[str]:
        findings: List[str] = []
        # Added specific payloads to test
        sql_payloads: List[str] = ["'", "' OR '1'='1"]
        forms: List[Tag] = self.extract_forms(self.target_url)
        
        for form in forms:
            for payload in sql_payloads:
                try:
                    response = self.submit_form(form, payload, self.target_url)
                    if "You have an error in your SQL syntax" in response.text or \
                       "mysql_fetch" in response.text:
                        action = str(form.get('action'))
                        
                        # UPDATED: Now includes the payload in the result
                        msg = f"Vulnerable Form: {action} | PAYLOAD: {payload}"
                        
                        if msg not in findings:
                            findings.append(msg)
                except:
                    continue
        return findings

    # --- Step 4: XSS ---
    def scan_xss(self) -> List[str]:
        findings: List[str] = []
        xss_payload: str = "<script>alert('XSS')</script>"
        forms: List[Tag] = self.extract_forms(self.target_url)
        
        for form in forms:
            try:
                response = self.submit_form(form, xss_payload, self.target_url)
                if xss_payload in response.content.decode():
                    action = str(form.get('action'))
                    
                    # UPDATED: Now includes the payload in the result
                    msg = f"XSS Found in: {action} | PAYLOAD: {xss_payload}"
                    
                    if msg not in findings:
                        findings.append(msg)
            except:
                continue
        return findings

# ==========================================
#  CLI WITH PROGRESS BAR
# ==========================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnSpectra CLI")
    parser.add_argument("url", help="Target URL")
    args = parser.parse_args()

    scanner = VulnerabilityScanner(args.url)
    
    steps = [
        ("Checking Security Headers...", scanner.check_security_headers),
        ("Scanning Open Ports...", scanner.scan_ports),
        ("Testing SQL Injection...", scanner.scan_sql_injection),
        ("Testing XSS Vulnerabilities...", scanner.scan_xss)
    ]
    
    print(f"\n[*] Starting Scan on: {args.url}\n")
    
    all_findings = {}
    total_steps = len(steps)
    
    for i, (msg, func) in enumerate(steps, 1):
        percent = int((i / total_steps) * 100)
        bar = '█' * (percent // 5) + '-' * ((100 - percent) // 5)
        print(f"\r[{bar}] {percent}% | {msg}", end="", flush=True)
        
        result = func()
        if result:
            all_findings[msg] = result
        time.sleep(0.5)

    print("\n\n" + "="*40)
    print(" SCAN COMPLETED ")
    print("="*40)

    if not all_findings:
        print("✅ No critical vulnerabilities found.")
    else:
        for category, issues in all_findings.items():
            print(f"\n❌ {category.replace('...', '')}:")
            for issue in issues:
                print(f"   - {issue}")
    print("\n")