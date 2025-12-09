import os
import json
from flask import Flask, render_template, request, jsonify, Response, stream_with_context
from scanner import VulnerabilityScanner
from colorama import init, Fore

# Initialize colorama for server logs
init(autoreset=True)

app = Flask(__name__)

# --- ROUTES ---

@app.route('/')
def home():
    return render_template('index.html')

# --- API ENDPOINTS (Called by JavaScript) ---

@app.route('/api/scan/headers', methods=['POST'])
def scan_headers_api():
    """Checks for missing security headers."""
    data = request.json
    url = data.get('url', '') # type: ignore
    
    print(f"{Fore.CYAN}[WEB] Scanning Headers for: {url}")
    scanner = VulnerabilityScanner(url)
    results = scanner.check_security_headers()
    return jsonify(results=results)

@app.route('/api/scan/ports', methods=['POST'])
def scan_ports_api():
    """Scans for open ports."""
    data = request.json
    url = data.get('url', '') # type: ignore
    
    print(f"{Fore.CYAN}[WEB] Scanning Ports for: {url}")
    scanner = VulnerabilityScanner(url)
    results = scanner.scan_ports()
    return jsonify(results=results)

@app.route('/api/scan/sql', methods=['POST'])
def scan_sql_api():
    data = request.json
    url = data.get('url', '') 
    payloads = data.get('payloads', []) 
    
    def generate():
        scanner = VulnerabilityScanner(url)
        # Iterate over the generator from scanner.py
        for update in scanner.scan_sql_injection(payloads):
            # Send as a JSON line + newline character
            yield json.dumps(update) + "\n"

    return Response(stream_with_context(generate()), mimetype='application/x-ndjson')

@app.route('/api/scan/xss', methods=['POST'])
def scan_xss_api():
    data = request.json
    url = data.get('url', '') 
    payloads = data.get('payloads', []) 
    
    def generate():
        scanner = VulnerabilityScanner(url)
        for update in scanner.scan_xss(payloads):
            yield json.dumps(update) + "\n"

    return Response(stream_with_context(generate()), mimetype='application/x-ndjson')

if __name__ == '__main__':
    app.run(debug=True, port=5000)