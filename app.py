from flask import Flask, render_template, request
from scanner import VulnerabilityScanner

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    # Fix: Default to empty string '' to prevent "None" type error
    target_url = request.form.get('url', '')
    
    # If the user didn't type anything, just reload the page
    if not target_url:
        return render_template('index.html', error="Please enter a valid URL.")

    # Initialize scanner
    scanner = VulnerabilityScanner(target_url)
    
    # Get the dictionary result
    scan_results = scanner.run_scan()
    
    # Pass results to the template
    return render_template('index.html', 
                           target_url=target_url,
                           scan_results=scan_results)

if __name__ == '__main__':
    app.run(debug=True)