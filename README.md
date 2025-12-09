<div align="center">

# 🛡️ VulnSpectra Pro
### Advanced Dual-Engine Web Vulnerability Scanner

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Web_Interface-green?style=for-the-badge&logo=flask&logoColor=white)
![Rich](https://img.shields.io/badge/CLI-Interactive-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-red?style=for-the-badge)

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-project-structure">Structure</a> •
  <a href="#-disclaimer">Disclaimer</a>
</p>

</div>

---

## 📖 Overview

**VulnSpectra** is a high-performance, multi-threaded penetration testing tool designed to detect common web vulnerabilities. It features a unique **Dual-Engine Architecture**, allowing users to operate via a robust **Interactive CLI** (inspired by tools like Loxs) or a modern **Web Dashboard** with real-time streaming results.

Built for speed and accuracy, VulnSpectra uses thread pooling to execute thousands of payload tests in seconds without freezing the user interface.

## 🚀 Features

### 🔥 Core Engines
* **Interactive CLI:** Beautiful ASCII-art interface using `Rich` and `Colorama`.
* **Web Dashboard:** Modern, responsive UI with real-time progress bars using Flask & Streaming API.

### ⚡ Performance & Capabilities
* **Multi-Threaded Scanning:** Spawns 10+ concurrent threads to process payloads 10x faster.
* **Real-Time Streaming:** Feedback is streamed instantly (Server-Sent Events style) via Generators; no waiting for the full scan to finish.
* **Dual Payload System:** Separate file uploaders for **SQL Injection** and **XSS**, preventing payload overlap.
* **Safety First:** Results are sanitized to prevent Self-XSS execution in the dashboard.

### 🎯 Attack Vectors
| Icon | Vector | Description |
| :---: | :--- | :--- |
| 🔒 | **Security Headers** | Checks for missing X-Frame-Options, CSP, HSTS, etc. |
| 🔌 | **Port Scanning** | Checks status of common ports (21, 22, 80, 443, 3306). |
| 💉 | **SQL Injection** | Fuzzes forms with error-based SQL payloads. |
| 💀 | **Cross-Site Scripting** | Tests inputs for Reflected XSS vulnerabilities. |

---

## 🛠️ Installation

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/Nakul-pejwar/VulnSpectra.git
    cd vulnspectra
    ```

2.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

    > **Note:** Ensure your `requirements.txt` includes: `requests`, `beautifulsoup4`, `flask`, `colorama`, `rich`.

---

## 💻 Usage

### Option 1: The Web Interface (GUI)
Run the Flask server to use the graphical dashboard with file uploads and progress bars.

```bash
python app.py

Open your browser to: http://127.0.0.1:5000

Enter the target URL.

(Optional) Upload custom .txt payload files for SQL or XSS.

Click Start Scan.
```

### Option 2: The Interactive CLI
Run the terminal version for a hacker-style experience.

```Bash

python scanner.py

Follow the interactive prompts.

Select attack vectors using the menu (1-5).

Load custom payloads when prompted.

```

### 📂 Project Structure

```bash
vulnspectra/
├── app.py                # Flask Web Server (Backend)
├── scanner.py            # Core Logic (Engine + CLI)
├── requirements.txt      # Python Dependencies
├── README.md             # Documentation
├── payloads/             # (Optional) Folder for default wordlists
│   ├── sql.txt
│   └── xss.txt
└── templates/
    └── index.html        # Web Dashboard Frontend
```
### 📸 Screenshots
### Web Dashboard
<img width="1366" height="624" alt="Screenshot From 2025-12-09 21-17-06" src="https://github.com/user-attachments/assets/a2c2099c-3e68-49a5-b3c0-beaa0be80c30" />

### Interactive CLI
<img width="1366" height="733" alt="Screenshot From 2025-12-09 21-37-42" src="https://github.com/user-attachments/assets/8e1e5379-12ae-42cd-99f2-0d8f7994e6d5" />

### ⚠️ Disclaimer

This tool is developed for educational purposes and ethical security testing only. 
The developer is not responsible for any misuse or damage caused by this tool. 
Only scan targets you own or have explicit permission to test.
🤝 Contributing
Contributions are welcome! Please fork the repository and submit a pull request.

Fork the Project

Create your Feature Branch (git checkout -b feature/AmazingFeature)

Commit your Changes (git commit -m 'Add some AmazingFeature')

Push to the Branch (git push origin feature/AmazingFeature)

Open a Pull Request

<div align="center"> <sub>Built with ❤️ using Python, Flask, and BeautifulSoup</sub> </div>
