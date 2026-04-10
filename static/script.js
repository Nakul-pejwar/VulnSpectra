const scanButton = document.getElementById('scanButton');
const targetUrl = document.getElementById('targetUrl');
const scanStatus = document.getElementById('scanStatus');
const scanProgressBar = document.getElementById('scanProgressBar');
const detailsContainer = document.getElementById('resultsDetail');
const faqItems = document.querySelectorAll('.accordion-item');
const uploadSql = document.getElementById('uploadSql');
const uploadXss = document.getElementById('uploadXss');
const sqlFileLabel = document.getElementById('sqlFileLabel');
const xssFileLabel = document.getElementById('xssFileLabel');

let customSqlPayloads = [];
let customXssPayloads = [];

const sanitizeText = (value) => {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return String(value).replace(/[&<>"']/g, (char) => map[char]);
};

const smoothScroll = () => {
  document.querySelectorAll('a[href^="#"]').forEach((link) => {
    link.addEventListener('click', (event) => {
      event.preventDefault();
      const target = document.querySelector(link.getAttribute('href'));
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });
};

const toggleFaq = () => {
  faqItems.forEach((item) => {
    const button = item.querySelector('.accordion-button');
    button.addEventListener('click', () => {
      const openItem = document.querySelector('.accordion-item.active');
      if (openItem && openItem !== item) {
        openItem.classList.remove('active');
      }
      item.classList.toggle('active');
    });
  });
};

const updateProgress = (percent, message) => {
  scanProgressBar.style.width = `${percent}%`;
  scanStatus.textContent = message;
};

const buildReportSummary = (score = 85, issues = 4, risk = 'Moderate') => {
  document.getElementById('securityScore').textContent = `${score}%`;
  document.getElementById('vulnerabilityCount').textContent = `${issues} Issues Found`;
  document.getElementById('riskLevel').textContent = risk;
  document.getElementById('scoreMeterFill').style.width = `${score}%`;
  document.getElementById('riskMeterFill').style.width = risk === 'High' ? '92%' : risk === 'Low' ? '36%' : '68%';
};

const createResultCard = (title, icon, items) => {
  const card = document.createElement('div');
  card.className = 'report-item';
  const list = items.length
    ? `<ul>${items.map((item) => `<li>${sanitizeText(item)}</li>`).join('')}</ul>`
    : '<p>No issues detected.</p>';
  card.innerHTML = `<strong>${icon} ${title}</strong>${list}`;
  detailsContainer.appendChild(card);
};

const createErrorCard = (title, message) => {
  const card = document.createElement('div');
  card.className = 'report-item';
  card.innerHTML = `<strong>${title}</strong><p>${sanitizeText(message)}</p>`;
  detailsContainer.appendChild(card);
};

const readPayloadFile = (fileInput, labelElement, targetArray) => {
  const file = fileInput.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (event) => {
    const lines = event.target.result
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    targetArray.splice(0, targetArray.length, ...lines);
    labelElement.textContent = `Loaded: ${lines.length} items`;
  };
  reader.readAsText(file);
};

const handleFlashResult = (results) => {
  const totalIssues = results.reduce((sum, item) => sum + item.issues.length, 0);
  const highCount = results.some((item) => item.issues.length > 0);
  const riskLevel = totalIssues >= 5 ? 'High' : highCount ? 'Moderate' : 'Low';
  buildReportSummary(85 - Math.min(totalIssues * 6, 55), totalIssues, riskLevel);
  detailsContainer.innerHTML = '';
  results.forEach((item) => createResultCard(item.title, item.icon, item.issues));
};

const fetchJsonStep = async (endpoint, payload = {}) => {
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || 'Request failed');
  }
  return response.json();
};

const startScan = async () => {
  const url = document.getElementById('targetUrl').value.trim();
  
  if (!url) {
    alert('Please enter a target URL');
    return;
  }
  
  // Validate URL format
  try {
    new URL(url);
  } catch {
    alert('Invalid URL format');
    return;
  }
  
  detailsContainer.innerHTML = '';
  scanStatus.textContent = 'Initializing scan...';
  scanProgressBar.style.width = '0%';
  
  const scans = [];
  
  if (document.getElementById('headersToggle').checked) {
    scans.push(
      fetchJsonStep('/api/scan/headers', { url }).then(res => ({
        title: 'Security Headers',
        icon: '🔒',
        issues: res.results
      }))
    );
  }
  
  if (document.getElementById('portsToggle').checked) {
    scans.push(
      fetchJsonStep('/api/scan/ports', { url }).then(res => ({
        title: 'Open Ports',
        icon: '🔌',
        issues: res.results
      }))
    );
  }
  
  if (document.getElementById('sqlToggle').checked) {
    scans.push(
      fetchStreamStep('/api/scan/sql', 
        { url, payloads: customSqlPayloads }, 
        'SQL Injection', 
        '💉'
      )
    );
  }
  
  if (document.getElementById('xssToggle').checked) {
    scans.push(
      fetchStreamStep('/api/scan/xss', 
        { url, payloads: customXssPayloads }, 
        'XSS', 
        '💀'
      )
    );
  }
  
  try {
    const results = await Promise.all(scans);
    handleFlashResult(results);
    scanStatus.textContent = 'Scan complete!';
    scanProgressBar.style.width = '100%';
  } catch (error) {
    createErrorCard('Scan Error', error.message);
    scanStatus.textContent = 'Scan failed: ' + error.message;
  }
};

window.addEventListener('DOMContentLoaded', () => {
  smoothScroll();
  toggleFaq();
  buildReportSummary();
  faqItems[0]?.classList.add('active');

  uploadSql.addEventListener('change', () => readPayloadFile(uploadSql, sqlFileLabel, customSqlPayloads));
  uploadXss.addEventListener('change', () => readPayloadFile(uploadXss, xssFileLabel, customXssPayloads));
  scanButton.addEventListener('click', startScan);
});
