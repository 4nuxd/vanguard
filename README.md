<div align="center">

# 🛡️ Vanguard Threat Engine

### Multipurpose Threat Intelligence Engine & SOC Incident Response Suite

An enterprise-grade, luxury glassmorphism Manifest V3 browser extension powered by VirusTotal, IPInfo.io, and AbuseIPDB. Highlights Indicators of Compromise (IPs, Domains, Hashes, URLs), parses defanged indicators, and delivers real-time threat intelligence inline.

<br />

[![Manifest V3](https://img.shields.io/badge/MANIFEST-V3-111111?style=for-the-badge&logo=googlechrome&logoColor=white)](manifest.json)
[![Chrome / Edge / Brave](https://img.shields.io/badge/CHROME%20%2F%20EDGE%20%2F%20BRAVE-MV3%20EXTENSION-3B82F6?style=for-the-badge&logo=googlechrome&logoColor=white)](#install-load-unpacked)
[![VirusTotal API v3](https://img.shields.io/badge/VIRUSTOTAL-API%20V3-2563EB?style=for-the-badge&logo=virustotal&logoColor=white)](https://virustotal.com)
[![IPInfo.io](https://img.shields.io/badge/IPINFO-GEO%20%26%20ISP-00E5FF?style=for-the-badge)](https://ipinfo.io)
[![AbuseIPDB](https://img.shields.io/badge/ABUSEIPDB-REPUTATION-FFC107?style=for-the-badge)](https://abuseipdb.com)
[![Release v3.0.0](https://img.shields.io/badge/RELEASE-V3.0.0-8B5CF6?style=for-the-badge&logo=github&logoColor=white)](#github-release-system)
[![License GPL-3.0](https://img.shields.io/badge/LICENSE-GPL--3.0-000000?style=for-the-badge)](LICENSE)

---

</div>

## Table of Contents
- [Overview](#overview)
- [Key Features](#key-features)
- [Install (Load Unpacked)](#install-load-unpacked)
- [Usage Guide](#usage-guide)
- [GitHub Release System & Building](#github-release-system--building)
- [Development & Project Structure](#development--project-structure)
- [License](#license)

---

## Overview
**VirusTotal Smart Inspector** is designed for security analysts, SOC responders, and threat hunters. It scans web pages for threat indicators, handles defanged indicators (e.g., `1.1.1[.]1`, `hxxps://`), excludes RFC 1918 private IPs automatically, and provides a built-in Batch IOC Scanner with multi-format SOC report exports (CSV, JSON, Markdown).

---

## Key Features
- 🔍 **Multi-IOC Recognition**: Auto-detects IPv4, IPv6, MD5, SHA-1, SHA-256 hashes, and domain names on any web page.
- 🛡️ **Defanging Support**: Automatically parses defanged indicators (e.g. `1.1.1[.]1`, `example[.]com`, `hxxps://`) and un-defangs them for VirusTotal queries.
- 🚫 **RFC 1918 Private IP Exclusion**: Skips internal private ranges (`10.x.x.x`, `192.168.x.x`, `127.0.0.1`, `localhost`) to save API quota.
- ⚡ **Context Menu Inspection**: Highlight text on any page, right-click, and select *"Inspect selection with VirusTotal"*.
- 📋 **Batch IOC Scanner**: Paste raw incident notes or server logs into the popup to extract, un-defang, and bulk-query all IOCs at once.
- 📊 **Enriched Intelligence**: Displays threat score rings, ASN/ISP details, vendor breakdown, and threat category tags.
- 📝 **SOC Incident Reports**: Export threat history as **CSV**, **JSON**, or formatted **Markdown Incident Reports** ready for Jira, GitHub, or ServiceNow.

---

## Install (Load Unpacked)
1. Clone or download this repository:
   ```bash
   git clone https://github.com/your-username/virustotal-smart-inspector.git
   ```
2. Open Chrome, Edge, or Brave and navigate to `chrome://extensions`.
3. Enable **Developer mode** (top-right toggle).
4. Click **Load unpacked** and select this repository folder.
5. Open the extension popup, click **Settings (⚙)**, and paste your VirusTotal v3 API key.

---

## Usage Guide
- **In-Page Tooltip**: Hover over highlighted indicators on any page to view inline reputation statistics.
- **Right-Click Context Menu**: Select any text on a page, right-click, and select *"Inspect selection with VirusTotal"*.
- **Quick Lookup Tab**: Perform instant search queries for single IPs, domains, hashes, or URLs.
- **Batch Scanner Tab**: Paste log blocks to extract and scan multiple IOCs simultaneously.
- **History & Reports**: Click *"View Full History & Reports"* to search, filter by IOC type, or export Markdown reports.

---

## GitHub Release System & Building

This repository features an automated build and GitHub Release system without external package manager dependencies.

### Local Package Building
To build a production `.zip` release archive locally:
```bash
bash scripts/build-release.sh
```
The packaged archive will be saved to `dist/virustotal-smart-inspector-v2.0.zip`.

### Automated GitHub Releases (CI/CD Workflow)
The repository includes a GitHub Actions workflow in `.github/workflows/release.yml`. When you push a new git release tag, GitHub Actions automatically validates the code, builds the release archive, and creates a GitHub Release with attached downloadable assets:

```bash
git tag v2.0.0
git push origin v2.0.0
```

---

## Development & Project Structure

```
virustotal-helper/
├── manifest.json                    # Extension MV3 configuration & permissions
├── README.md                        # Project documentation & shields
├── LICENSE                          # License terms
├── icons/                           # Extension icons
├── scripts/
│   └── build-release.sh            # Release build & packaging script
├── .github/
│   └── workflows/
│       └── release.yml              # GitHub Actions automated release workflow
└── src/
    ├── background/
    │   └── background.js            # API wrapper, caching, contextMenus & rate-limiting
    ├── content/
    │   ├── content.js               # Multi-IOC regex matching & tooltip DOM injection
    │   └── tooltip.css              # Glassmorphism tooltip styles
    ├── popup/
    │   ├── popup.html               # Tabbed UI (Quick Lookup + Batch Scanner)
    │   └── popup.js                 # Search debouncing, batch processing & settings
    ├── options/
    │   ├── history.html             # History grid & export UI
    │   └── history.js               # Search filtering, CSV/JSON/Markdown exporters
    └── styles/
        └── styles.css               # Core design system & theme styling
```

---

## License
Distributed under the [GPL-3.0 License](LICENSE).
