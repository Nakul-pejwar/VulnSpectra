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

const fetchStreamStep = async (endpoint, payload, title, icon) => {
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(errorText || 'Request failed');
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  const issues = [];

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const parts = buffer.split('\n');
    buffer = parts.pop();
    for (const part of parts) {
      if (!part.trim()) continue;
      try {
        const payload = JSON.parse(part);
        if (payload.type === 'finding') {
          issues.push(payload.data);
          updateProgress(Math.min(90, 40 + issues.length * 5), `Detecting ${title}: ${issues.length} findings`);
        }
      } catch (err) {
        console.warn('Stream parse failed', err);
      }
    }
  }
  return { title, icon, issues };
};

const startScan = async () => {
  const url = targetUrl.value.trim();
  if (!url) {
    targetUrl.focus();
    return;
  }

  scanButton.disabled = true;
  updateProgress(8, 'Launching scan engine...');
  detailsContainer.innerHTML = '';

  const results = [];
  const activeHeaders = document.getElementById('headersToggle').checked;
  const activePorts = document.getElementById('portsToggle').checked;
  const activeSql = document.getElementById('sqlToggle').checked;
  const activeXss = document.getElementById('xssToggle').checked;

  try {
    if (activeHeaders) {
      updateProgress(18, 'Checking security headers...');
      const json = await fetchJsonStep('/api/scan/headers', { url });
      results.push({ title: 'Security Headers', icon: '🔒', issues: json.results || [] });
    }
    if (activePorts) {
      updateProgress(30, 'Scanning open ports...');
      const json = await fetchJsonStep('/api/scan/ports', { url });
      results.push({ title: 'Open Ports', icon: '🔌', issues: json.results || [] });
    }
    if (activeSql) {
      updateProgress(46, 'Fuzzing SQL injection...');
      const sqlResult = await fetchStreamStep('/api/scan/sql', { url, payloads: customSqlPayloads }, 'SQL Injection', '💉');
      results.push(sqlResult);
    }
    if (activeXss) {
      updateProgress(62, 'Testing XSS attack vectors...');
      const xssResult = await fetchStreamStep('/api/scan/xss', { url, payloads: customXssPayloads }, 'XSS Scanner', '💀');
      results.push(xssResult);
    }

    updateProgress(100, 'Scan complete. Review the dashboard.');
    handleFlashResult(results);
  } catch (error) {
    createErrorCard('Scan error', error.message || 'Unable to complete request.');
    updateProgress(100, 'Scan interrupted.');
  } finally {
    scanButton.disabled = false;
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
