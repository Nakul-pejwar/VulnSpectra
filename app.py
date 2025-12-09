from flask import Flask, render_template, request, jsonify
from scanner import VulnerabilityScanner

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/scan/headers', methods=['POST'])
def scan_headers_api():
    data = request.json
    url = data.get('url', '') # type: ignore
    scanner = VulnerabilityScanner(url)
    results = scanner.check_security_headers()
    return jsonify(results=results)

@app.route('/api/scan/ports', methods=['POST'])
def scan_ports_api():
    data = request.json
    url = data.get('url', '') # type: ignore
    scanner = VulnerabilityScanner(url)
    results = scanner.scan_ports()
    return jsonify(results=results)

@app.route('/api/scan/sql', methods=['POST'])
def scan_sql_api():
    data = request.json
    url = data.get('url', '') # type: ignore
    payloads = data.get('payloads', []) # type: ignore
    scanner = VulnerabilityScanner(url)
    results = scanner.scan_sql_injection(payloads)
    return jsonify(results=results)

@app.route('/api/scan/xss', methods=['POST'])
def scan_xss_api():
    data = request.json
    url = data.get('url', '') # type: ignore
    payloads = data.get('payloads', []) # type: ignore
    scanner = VulnerabilityScanner(url)
    results = scanner.scan_xss(payloads)
    return jsonify(results=results)

if __name__ == '__main__':
    app.run(debug=True)