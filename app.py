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
    url = data.get('url', '').strip() # type: ignore
    
    if not url:
        return jsonify(error="Missing URL"), 400
    
    # Validate URL format
    try:
        from urllib.parse import urlparse
        result = urlparse(url)
        if not result.scheme or result.scheme not in ('http', 'https'):
            return jsonify(error="URL must start with http:// or https://"), 400
        if not result.netloc:
            return jsonify(error="Invalid URL format"), 400
    except Exception as e:
        return jsonify(error=f"URL validation failed: {str(e)}"), 400

    print(f"{Fore.CYAN}[WEB] Scanning Headers for: {url}")
    scanner = VulnerabilityScanner(url)
    results = scanner.check_security_headers()
    return jsonify(results=results)

@app.route('/api/scan/ports', methods=['POST'])
def scan_ports_api():
    """Scans for open ports."""
    data = request.json
    url = data.get('url', '').strip() # type: ignore
    
    if not url:
        return jsonify(error="Missing URL"), 400
    
    # Validate URL format
    try:
        from urllib.parse import urlparse
        result = urlparse(url)
        if not result.scheme or result.scheme not in ('http', 'https'):
            return jsonify(error="URL must start with http:// or https://"), 400
        if not result.netloc:
            return jsonify(error="Invalid URL format"), 400
    except Exception as e:
        return jsonify(error=f"URL validation failed: {str(e)}"), 400

    print(f"{Fore.CYAN}[WEB] Scanning Ports for: {url}")
    scanner = VulnerabilityScanner(url)
    results = scanner.scan_ports()
    return jsonify(results=results)

@app.route('/api/scan/sql', methods=['POST'])
def scan_sql_api():
    data = request.json
    url = data.get('url', '').strip()
    payloads = data.get('payloads', []) 

    if not url:
        return jsonify(error="Missing URL"), 400
    
    # Validate URL format
    try:
        from urllib.parse import urlparse
        result = urlparse(url)
        if not result.scheme or result.scheme not in ('http', 'https'):
            return jsonify(error="URL must start with http:// or https://"), 400
        if not result.netloc:
            return jsonify(error="Invalid URL format"), 400
    except Exception as e:
        return jsonify(error=f"URL validation failed: {str(e)}"), 400

    def generate():
        try:
            scanner = VulnerabilityScanner(url)
            for update in scanner.scan_sql_injection(payloads):
                yield json.dumps(update) + "\n"
        except Exception as exc:
            yield json.dumps({"type": "error", "msg": str(exc)}) + "\n"

    return Response(stream_with_context(generate()), mimetype='application/x-ndjson')

@app.route('/api/scan/xss', methods=['POST'])
def scan_xss_api():
    data = request.json
    url = data.get('url', '').strip() 
    payloads = data.get('payloads', []) 

    if not url:
        return jsonify(error="Missing URL"), 400
    
    # Validate URL format
    try:
        from urllib.parse import urlparse
        result = urlparse(url)
        if not result.scheme or result.scheme not in ('http', 'https'):
            return jsonify(error="URL must start with http:// or https://"), 400
        if not result.netloc:
            return jsonify(error="Invalid URL format"), 400
    except Exception as e:
        return jsonify(error=f"URL validation failed: {str(e)}"), 400

    def generate():
        try:
            scanner = VulnerabilityScanner(url)
            for update in scanner.scan_xss(payloads):
                yield json.dumps(update) + "\n"
        except Exception as exc:
            yield json.dumps({"type": "error", "msg": str(exc)}) + "\n"

    return Response(stream_with_context(generate()), mimetype='application/x-ndjson')

if __name__ == '__main__':
    app.run(debug=True, port=5000)