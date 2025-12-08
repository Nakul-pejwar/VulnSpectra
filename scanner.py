import requests
from bs4 import BeautifulSoup, Tag
from urllib.parse import urljoin
from typing import Optional, List, Dict, Any

class VulnerabilityScanner:
    def __init__(self, target_url: str, session: Optional[requests.Session] = None):
        self.target_url: str = target_url
        self.session: requests.Session = session or requests.Session()
        # This list will store findings to show on the webpage
        self.vulns_found: List[str] = []

    def run_scan(self) -> List[str]:
        """
        Master function called by app.py.
        Runs all checks and returns the list of findings.
        """
        self.vulns_found = [] # Clear previous results
        
        print(f"[*] Starting scan on {self.target_url}...")
        
        # 1. Check Headers
        self.check_security_headers(self.target_url)
        
        # 2. Check SQL Injection
        self.scan_sql_injection(self.target_url)
        
        # 3. Check XSS
        self.scan_xss(self.target_url)
        
        return self.vulns_found

    def extract_forms(self, url: str) -> List[Tag]:
        response: requests.Response = self.session.get(url)
        soup: BeautifulSoup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")

    def submit_form(self, form: Tag, value: str, url: str) -> requests.Response:
        action: Optional[str] = form.get("action") # type: ignore
        post_url: str = urljoin(url, action) if action else url
        method: Optional[str] = form.get("method") # type: ignore

        inputs_list: List[Tag] = form.find_all("input")
        post_data: Dict[str, Any] = {}
        
        for input_tag in inputs_list:
            input_name: Optional[str] = input_tag.get("name") # type: ignore
            input_type: Optional[str] = input_tag.get("type") # type: ignore
            input_value: Optional[str] = input_tag.get("value") # type: ignore
            
            if input_type == "text":
                input_value = value
            
            if input_name:
                post_data[input_name] = input_value
        
        if method and method.lower() == "post":
            return self.session.post(post_url, data=post_data)
        return self.session.get(post_url, params=post_data)

    def scan_sql_injection(self, url: str) -> bool:
        sql_payloads: List[str] = ["'", "\"", "' OR '1'='1"]
        forms: List[Tag] = self.extract_forms(url)
        
        for form in forms:
            for payload in sql_payloads:
                response: requests.Response = self.submit_form(form, payload, url)
                if "You have an error in your SQL syntax" in response.text or \
                   "mysql_fetch" in response.text:
                    msg = f"SQL Injection vulnerability found in {url} using payload: {payload}"
                    self.vulns_found.append(msg)
                    print(f"[!] {msg}")
                    return True
        return False

    def scan_xss(self, url: str) -> bool:
        xss_payload: str = "<script>alert('XSS')</script>"
        forms: List[Tag] = self.extract_forms(url)
        
        for form in forms:
            response: requests.Response = self.submit_form(form, xss_payload, url)
            if xss_payload in response.content.decode():
                msg = f"XSS vulnerability found in {url} with payload: {xss_payload}"
                self.vulns_found.append(msg)
                print(f"[!] {msg}")
                return True
        return False

    def check_security_headers(self, url: str) -> None:
        try:
            response: requests.Response = self.session.get(url)
            headers = response.headers
            
            required_headers: List[str] = [
                "X-Frame-Options",
                "X-XSS-Protection",
                "Content-Security-Policy",
                "Strict-Transport-Security"
            ]

            missing = [h for h in required_headers if h not in headers]
            
            if missing:
                msg = f"Missing Security Headers: {', '.join(missing)}"
                self.vulns_found.append(msg)
                print(f"[!] {msg}")
            else:
                self.vulns_found.append("Security Headers are configured correctly.")

        except requests.exceptions.RequestException as e:
            self.vulns_found.append(f"Error connecting to URL: {str(e)}")