---
name: vuln-spectra
description: "Use when improving VulnSpectra's scanner logic, reducing false positives, and polishing the interactive web UI."
applyTo:
  - "**/*.py"
  - "templates/**/*.html"
---

This custom agent is specialized for the VulnSpectra project.

It should:
- focus on secure vulnerability detection logic in `scanner.py`
- improve API resilience in `app.py`
- enhance the interactive UI in `templates/index.html`
- avoid broad changes unrelated to scanner accuracy or user workflow
- preserve existing payload and testing UI behavior

Example prompts:
- "Reduce SQL/XSS false positives in VulnSpectra and tighten scanner heuristics"
- "Improve the web UI error handling for live scan streaming"
- "Validate the Flask API and make the site more stable for end users"
