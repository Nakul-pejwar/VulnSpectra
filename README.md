<div align="center">

# 🛡️ VulnSpectra Pro
### Dual-Engine Web Vulnerability Scanner

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Web_Interface-green?style=for-the-badge&logo=flask&logoColor=white)
![Rich](https://img.shields.io/badge/CLI-Interactive-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-red?style=for-the-badge)

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#project-structure">Structure</a> •
  <a href="#disclaimer">Disclaimer</a>
</p>

</div>

---

## 📖 Overview

**VulnSpectra** is a Python web vulnerability scanner that combines a Flask-based dashboard and an interactive terminal interface. It scans target websites for missing security headers, open ports, SQL injection, and reflected XSS by parsing HTML forms, submitting payloads, and analyzing responses.

The project is centered on `scanner.py` for scan logic and form handling, while `app.py` exposes API endpoints used by the web frontend. Multithreading is used to speed up payload testing, and the web UI streams scan progress back to the browser.

## 🚀 Features

### 🔥 Dual Engines
* **Interactive CLI** — terminal scanner with a menu-driven interface, progress bars, and summaries.
* **Web Dashboard** — Flask app with JSON APIs and real-time scan streaming.

### ⚡ Core Capabilities
* **Form-based scanning** for SQL injection and reflected XSS.
* **Security header checks** for `X-Frame-Options`, `X-XSS-Protection`, and `Content-Security-Policy`.
* **Common port probing** on ports `21`, `22`, `80`, `443`, and `3306`.
* **Custom payload support** by loading SQL or XSS payload files.
* **Threaded scanning** using a thread pool to keep scans fast and responsive.

### 🎯 What the Scanner Does
* Loads forms from a target URL using `BeautifulSoup`.
* Builds form submission data and submits payloads via `requests`.
* Detects SQL injection by searching responses for database error signatures.
* Detects reflected XSS when payload content appears in the returned HTML.
* Streams SQL and XSS scan updates from the backend to the frontend.

---

## 🛠️ Installation

1.  **Clone the repository**
    ```bash
    git clone https://github.com/Nakul-pejwar/VulnSpectra.git
    cd VulnSpectra
    ```

2.  **Install dependencies**
    ```bash
    pip install -r requirements.txt
    ```

> Recommended dependencies: `requests`, `beautifulsoup4`, `flask`, `colorama`, `rich`.

---

## 💻 Usage

### Option 1: Web Dashboard
Start the Flask server:

```bash
python app.py
```

Then open `http://127.0.0.1:5000` in your browser. Enter a target URL, choose a scan type, and optionally upload a SQL or XSS payload file.

### Option 2: Interactive CLI
Run the terminal scanner:

```bash
python scanner.py
```

Follow the prompts to enter a target URL, choose a scan vector, and optionally load custom payloads.

### Supported Scan Types
* **Security Headers** — checks for missing headers.
* **Port Scan** — probes common service ports.
* **SQL Injection** — fuzzes HTML forms with SQL payloads.
* **XSS** — tests forms for reflected cross-site scripting.

---

## 📂 Project Structure

```bash
VulnSpectra/
├── app.py                # Flask web server and API endpoints
├── scanner.py            # Core scanning engine and CLI logic
├── requirements.txt      # Python dependencies
├── README.md             # Project documentation
├── payloads/             # Default payload wordlists
│   ├── sql.txt
│   └── xss.txt
└── templates/
    └── index.html        # Web dashboard frontend
```

---

## ⚠️ Disclaimer

This tool is intended for educational and authorized security testing only. Do not use it against systems without permission. The author is not responsible for misuse or any damage caused by unauthorized scanning.

## 🤝 Contributing

Contributions are welcome. Fork the repository, create a feature branch, and submit a pull request.

<div align="center"> <sub>Built with ❤️ using Python, Flask, and BeautifulSoup</sub> </div>
