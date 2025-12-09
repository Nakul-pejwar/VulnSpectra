import requests
import socket
import sys
import os
import time
from bs4 import BeautifulSoup, Tag
from urllib.parse import urljoin
from typing import Optional, List, Dict, Any, Union

# UI Libraries
from colorama import init, Fore, Style
from rich.console import Console
from rich.panel import Panel

# Initialize Colorama and Rich
init(autoreset=True)
console = Console()

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
            
            if input_type == "text":
                if input_name:
                    post_data[input_name] = value
            elif input_name:
                post_data[input_name] = input_val
        
        if method.lower() == "post":
            return self.session.post(post_url, data=post_data, timeout=10)
        return self.session.get(post_url, params=post_data, timeout=10)

    # --- SCANNERS ---
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

    def scan_sql_injection(self, custom_payloads: List[str] = []) -> List[str]:
        findings: List[str] = []
        sql_payloads: List[str] = custom_payloads if custom_payloads else ["'", "' OR '1'='1", '" OR "1"="1']
        forms: List[Tag] = self.extract_forms(self.target_url)
        
        print(f"{Fore.YELLOW}[*] Scanning {len(forms)} forms with {len(sql_payloads)} payloads...")
        
        for form in forms:
            for payload in sql_payloads:
                try:
                    response = self.submit_form(form, payload, self.target_url)
                    if "You have an error in your SQL syntax" in response.text or \
                       "mysql_fetch" in response.text:
                        action = str(form.get('action'))
                        msg = f"Vulnerable Form: {action} | PAYLOAD: {payload}"
                        if msg not in findings:
                            findings.append(msg)
                            print(f"{Fore.GREEN}[+] FOUND: {msg}")
                except:
                    continue
        return findings

    def scan_xss(self, custom_payloads: List[str] = []) -> List[str]:
        findings: List[str] = []
        xss_payloads: List[str] = custom_payloads if custom_payloads else ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]
        forms: List[Tag] = self.extract_forms(self.target_url)
        
        print(f"{Fore.YELLOW}[*] Scanning {len(forms)} forms with {len(xss_payloads)} payloads...")

        for form in forms:
            for payload in xss_payloads:
                try:
                    response = self.submit_form(form, payload, self.target_url)
                    if payload in response.content.decode():
                        action = str(form.get('action'))
                        msg = f"XSS Found in: {action} | PAYLOAD: {payload}"
                        if msg not in findings:
                            findings.append(msg)
                            print(f"{Fore.GREEN}[+] FOUND: {msg}")
                except:
                    continue
        return findings

# ==========================================
#  NEW INTERACTIVE CLI (LOXS STYLE)
# ==========================================

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_banner():
    # Similar style to LOXS panel
    panel = Panel(
        r"""
██    ██ ██    ██ ██      ███    ██ ███████ ██████  ███████  ██████ ████████ ██████   █████  
██    ██ ██    ██ ██      ████   ██ ██      ██   ██ ██      ██         ██    ██   ██ ██   ██ 
██    ██ ██    ██ ██      ██ ██  ██ ███████ ██████  █████   ██         ██    ██████  ███████ 
 ██  ██  ██    ██ ██      ██  ██ ██      ██ ██      ██      ██         ██    ██   ██ ██   ██ 
  ████    ██████  ███████ ██   ████ ███████ ██      ███████  ██████    ██    ██   ██ ██   ██ 
        """,
        title="[bold green]VULNSPECTRA v2.0[/bold green]",
        subtitle="[cyan]Automated Web Vulnerability Scanner[/cyan]",
        style="bold blue",
        border_style="cyan",
        expand=False
    )
    console.print(panel)
    print(f"\n{Fore.CYAN}Created by: You | Style inspired by LOXS\n")

def get_file_payloads(prompt_text: str) -> List[str]:
    file_path = input(prompt_text).strip()
    if not file_path:
        return []
    
    if not os.path.isfile(file_path):
        print(f"{Fore.RED}[!] File not found: {file_path}. Using default payloads.")
        return []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"{Fore.RED}[!] Error reading file: {e}")
        return []

def print_summary(findings: List[str]):
    if not findings:
        print(f"\n{Fore.RED}[-] No vulnerabilities found in this scan.")
    else:
        print(f"\n{Fore.GREEN}[+] Scan Complete! Findings:")
        for f in findings:
            print(f"{Fore.GREEN} -> {f}")
    
    print(f"\n{Fore.CYAN}" + "="*50 + "\n")

def main():
    while True:
        clear_screen()
        display_banner()
        
        # 1. Ask for URL
        target_url = input(f"{Fore.YELLOW}[?] Enter Target URL (e.g., http://testphp.vulnweb.com): {Style.RESET_ALL}").strip()
        
        if not target_url:
            print(f"{Fore.RED}[!] URL is required.")
            time.sleep(1)
            continue

        scanner = VulnerabilityScanner(target_url)

        # 2. Display Menu
        print(f"\n{Fore.CYAN}[?] Select Attack Vector:")
        print(f"{Fore.WHITE}1] {Fore.GREEN}Check Security Headers")
        print(f"{Fore.WHITE}2] {Fore.GREEN}Scan Open Ports")
        print(f"{Fore.WHITE}3] {Fore.GREEN}SQL Injection Scanner")
        print(f"{Fore.WHITE}4] {Fore.GREEN}XSS Scanner")
        print(f"{Fore.WHITE}5] {Fore.GREEN}Run ALL Scans")
        print(f"{Fore.WHITE}0] {Fore.RED}Exit")

        choice = input(f"\n{Fore.YELLOW}[>] Select an option (0-5): {Style.RESET_ALL}").strip()

        payloads: List[str] = []

        # 3. Handle Payloads (Only if needed)
        if choice in ['3', '4', '5']:
            use_custom = input(f"{Fore.CYAN}[?] Do you want to load a custom payload file? (y/n): {Style.RESET_ALL}").lower()
            if use_custom == 'y':
                payloads = get_file_payloads(f"{Fore.YELLOW}[?] Enter path to payload file (e.g., payloads.txt): {Style.RESET_ALL}")
                if payloads:
                    print(f"{Fore.GREEN}[*] Loaded {len(payloads)} custom payloads.")

        print(f"\n{Fore.CYAN}[*] Starting Scan on {target_url}...\n")
        
        # 4. Execute Logic
        results = []
        
        if choice == '1':
            results = scanner.check_security_headers()
            print_summary(results)
            
        elif choice == '2':
            results = scanner.scan_ports()
            print_summary(results)
            
        elif choice == '3':
            results = scanner.scan_sql_injection(payloads)
            print_summary(results)
            
        elif choice == '4':
            results = scanner.scan_xss(payloads)
            print_summary(results)
            
        elif choice == '5':
            print(f"{Fore.MAGENTA}--- HEADERS ---")
            print_summary(scanner.check_security_headers())
            
            print(f"{Fore.MAGENTA}--- PORTS ---")
            print_summary(scanner.scan_ports())
            
            print(f"{Fore.MAGENTA}--- SQL INJECTION ---")
            print_summary(scanner.scan_sql_injection(payloads))
            
            print(f"{Fore.MAGENTA}--- XSS ---")
            print_summary(scanner.scan_xss(payloads))

        elif choice == '0':
            print(f"{Fore.RED}\n[!] Exiting VulnSpectra. Goodbye!")
            sys.exit()
        
        else:
            print(f"{Fore.RED}[!] Invalid Selection.")

        input(f"{Fore.YELLOW}[i] Press Enter to scan another target...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Exiting...")
        sys.exit()