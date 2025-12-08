from flask import Flask, render_template, request
from scanner import VulnerabilityScanner

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.form['url']
    if not target_url.startswith('http'):
        target_url = 'http://' + target_url
    
    scanner = VulnerabilityScanner(target_url)
    results = scanner.run_scan()
    
    return render_template('index.html', results=results, target=target_url)

if __name__ == '__main__':
    app.run(debug=True)