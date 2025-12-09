import requests
import socket
import sys
import os
import time
import concurrent.futures
from bs4 import BeautifulSoup, Tag
from urllib.parse import urljoin
from typing import Optional, List, Dict, Any, Union, Generator

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
        # Threading pool size (Safe number to avoid crashing sites)
        self.max_threads = 10 

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
        
        try:
            if method.lower() == "post":
                return self.session.post(post_url, data=post_data, timeout=5)
            return self.session.get(post_url, params=post_data, timeout=5)
        except requests.exceptions.RequestException:
            # Return a dummy object if connection fails to keep threads alive
            dummy = requests.Response()
            dummy.status_code = 0
            return dummy

    # --- HELPER: Single Payload Check (Runs in a Thread) ---
    def _test_sql_payload(self, form: Tag, payload: str) -> Optional[str]:
        response = self.submit_form(form, payload, self.target_url)
        if "You have an error in your SQL syntax" in response.text or \
           "mysql_fetch" in response.text:
            action = str(form.get('action'))
            return f"Vulnerable Form: {action} | PAYLOAD: {payload}"
        return None

    def _test_xss_payload(self, form: Tag, payload: str) -> Optional[str]:
        response = self.submit_form(form, payload, self.target_url)
        if payload in response.content.decode():
            action = str(form.get('action'))
            return f"XSS Found in: {action} | PAYLOAD: {payload}"
        return None

    # --- SCANNERS (Standard Lists) ---
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
        
        # Ports are fast enough to run sequentially or with small socket timeouts
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

    # --- SCANNERS (Threaded Generators) ---
    def scan_sql_injection(self, custom_payloads: List[str] = []) -> Generator[Dict[str, Any], None, None]:
        sql_payloads = custom_payloads if custom_payloads else ["'", "' OR '1'='1", '" OR "1"="1']
        forms = self.extract_forms(self.target_url)
        
        total_scans = len(forms) * len(sql_payloads)
        current_scan = 0
        
        yield {"type": "info", "msg": f"Found {len(forms)} forms. Spawning {self.max_threads} threads for {len(sql_payloads)} payloads..."}

        if total_scans == 0:
            yield {"type": "progress", "percent": 100}
            return

        # Create Thread Pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Dictionary to map futures to payloads (optional, for debugging)
            futures = []
            
            # Queue up all jobs
            for form in forms:
                for payload in sql_payloads:
                    futures.append(executor.submit(self._test_sql_payload, form, payload))
            
            # Process results as they finish (Streaming)
            for future in concurrent.futures.as_completed(futures):
                current_scan += 1
                percent = int((current_scan / total_scans) * 100)
                yield {"type": "progress", "percent": percent}

                try:
                    result = future.result()
                    if result:
                         yield {"type": "finding", "data": result}
                except Exception:
                    continue

    def scan_xss(self, custom_payloads: List[str] = []) -> Generator[Dict[str, Any], None, None]:
        xss_payloads = custom_payloads if custom_payloads else ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]
        forms = self.extract_forms(self.target_url)
        
        total_scans = len(forms) * len(xss_payloads)
        current_scan = 0
        
        yield {"type": "info", "msg": f"Found {len(forms)} forms. Spawning {self.max_threads} threads for {len(xss_payloads)} payloads..."}

        if total_scans == 0:
            yield {"type": "progress", "percent": 100}
            return

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            
            for form in forms:
                for payload in xss_payloads:
                    futures.append(executor.submit(self._test_xss_payload, form, payload))
            
            for future in concurrent.futures.as_completed(futures):
                current_scan += 1
                percent = int((current_scan / total_scans) * 100)
                yield {"type": "progress", "percent": percent}

                try:
                    result = future.result()
                    if result:
                         yield {"type": "finding", "data": result}
                except Exception:
                    continue

# ==========================================
#  CLI LOGIC
# ==========================================

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_banner():
    panel = Panel(
        r"""
██    ██ ██    ██ ██      ███    ██ ███████ ██████  ███████  ██████ ████████ ██████   █████  
██    ██ ██    ██ ██      ████   ██ ██      ██   ██ ██      ██         ██    ██   ██ ██   ██ 
██    ██ ██    ██ ██      ██ ██  ██ ███████ ██████  █████   ██         ██    ██████  ███████ 
 ██  ██  ██    ██ ██      ██  ██ ██      ██ ██      ██      ██         ██    ██   ██ ██   ██ 
  ████    ██████  ███████ ██   ████ ███████ ██      ███████  ██████    ██    ██   ██ ██   ██ 
        """,
        title="[bold green]VULNSPECTRA PRO (Multi-Threaded)[/bold green]",
        subtitle="[cyan]High-Speed Web Vulnerability Scanner[/cyan]",
        style="bold blue",
        border_style="cyan",
        expand=False
    )
    console.print(panel)
    print(f"\n{Fore.CYAN}Created by: You | Speed Optimized\n")

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

def handle_scan_result(scan_result: Union[List[str], Generator]) -> List[str]:
    findings = []
    
    if isinstance(scan_result, list):
        return scan_result
    
    try:
        for update in scan_result:
            if update['type'] == 'progress':
                percent = update['percent']
                bar_length = 30
                filled_length = int(bar_length * percent // 100)
                bar = '█' * filled_length + '-' * (bar_length - filled_length)
                sys.stdout.write(f"\r{Fore.YELLOW}[{bar}] {percent}% ")
                sys.stdout.flush()
                
            elif update['type'] == 'finding':
                findings.append(update['data'])
                sys.stdout.write("\r" + " " * 50 + "\r") 
                print(f"{Fore.GREEN}[+] FOUND: {update['data']}")
                
            elif update['type'] == 'info':
                sys.stdout.write("\r" + " " * 50 + "\r")
                print(f"{Fore.CYAN}[i] {update['msg']}")
                
        print(f"\r{Fore.GREEN}[*] Scan Complete!                                   ")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error reading scan stream: {e}")
        
    return findings

def print_summary(findings: List[str]):
    if not findings:
        print(f"\n{Fore.RED}[-] No vulnerabilities found in this scan.")
    else:
        print(f"\n{Fore.GREEN}[+] Scan Summary:")
        for f in findings:
            print(f"{Fore.GREEN} -> {f}")
    
    print(f"\n{Fore.CYAN}" + "="*50 + "\n")

def main():
    while True:
        clear_screen()
        display_banner()
        
        target_url = input(f"{Fore.YELLOW}[?] Enter Target URL (e.g., http://testphp.vulnweb.com): {Style.RESET_ALL}").strip()
        
        if not target_url:
            print(f"{Fore.RED}[!] URL is required.")
            time.sleep(1)
            continue

        scanner = VulnerabilityScanner(target_url)

        print(f"\n{Fore.CYAN}[?] Select Attack Vector:")
        print(f"{Fore.WHITE}1] {Fore.GREEN}Check Security Headers")
        print(f"{Fore.WHITE}2] {Fore.GREEN}Scan Open Ports")
        print(f"{Fore.WHITE}3] {Fore.GREEN}SQL Injection Scanner")
        print(f"{Fore.WHITE}4] {Fore.GREEN}XSS Scanner")
        print(f"{Fore.WHITE}5] {Fore.GREEN}Run ALL Scans")
        print(f"{Fore.WHITE}0] {Fore.RED}Exit")

        choice = input(f"\n{Fore.YELLOW}[>] Select an option (0-5): {Style.RESET_ALL}").strip()

        payloads: List[str] = []

        if choice in ['3', '4', '5']:
            use_custom = input(f"{Fore.CYAN}[?] Do you want to load a custom payload file? (y/n): {Style.RESET_ALL}").lower()
            if use_custom == 'y':
                payloads = get_file_payloads(f"{Fore.YELLOW}[?] Enter path to payload file (e.g., payloads.txt): {Style.RESET_ALL}")
                if payloads:
                    print(f"{Fore.GREEN}[*] Loaded {len(payloads)} custom payloads.")

        print(f"\n{Fore.CYAN}[*] Starting Scan on {target_url}...\n")
        
        if choice == '1':
            results = handle_scan_result(scanner.check_security_headers())
            print_summary(results)
            
        elif choice == '2':
            results = handle_scan_result(scanner.scan_ports())
            print_summary(results)
            
        elif choice == '3':
            results = handle_scan_result(scanner.scan_sql_injection(payloads))
            print_summary(results)
            
        elif choice == '4':
            results = handle_scan_result(scanner.scan_xss(payloads))
            print_summary(results)
            
        elif choice == '5':
            print(f"{Fore.MAGENTA}--- HEADERS ---")
            print_summary(handle_scan_result(scanner.check_security_headers()))
            
            print(f"{Fore.MAGENTA}--- PORTS ---")
            print_summary(handle_scan_result(scanner.scan_ports()))
            
            print(f"{Fore.MAGENTA}--- SQL INJECTION ---")
            print_summary(handle_scan_result(scanner.scan_sql_injection(payloads)))
            
            print(f"{Fore.MAGENTA}--- XSS ---")
            print_summary(handle_scan_result(scanner.scan_xss(payloads)))

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