# VirusTotal Smart Inspector

> Highlight IPs on pages and get instant VirusTotal reputation, history, and quick lookups.

**Version:** 1.0 • **Manifest:** MV3

## Table of Contents
- [What It Does](#what-it-does)
- [Features](#features)
- [Install (Load Unpacked)](#install-load-unpacked)
- [Usage](#usage)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## What It Does
VirusTotal Smart Inspector is a lightweight browser extension that highlights IPs and other indicators on webpages and surfaces VirusTotal reputation details instantly via popups, context menus, and inline tooltips.

## Features
- Highlight IPs and common indicators on any webpage
- Quick popup search and inline tooltip previews
- Context menu lookup for selected text
- Persistent lookup history accessible from the extension's `History` page
- Runs as a Manifest V3 extension with a service worker background script

## Install (Load Unpacked)
1. Clone or download this repository.
2. Open your Chromium-based browser (Chrome, Edge, Brave) and go to `chrome://extensions`.
3. Enable `Developer mode` (top-right).
4. Click `Load unpacked` and select this repository folder.
5. Pin the extension and open the popup to start using it.

Notes:
- The extension requests host permissions to access VirusTotal pages and to inject content scripts (`<all_urls>`). Grant permissions when prompted.

## Usage
- Click the extension icon to open the popup for quick searches.
- Right-click selected text and choose the VirusTotal lookup entry from the context menu.
- Hover over highlighted indicators to see inline tooltips with summary information.
- Open the `History` page (via the popup or extension options) to review past lookups and clear storage.

## Development
- This project uses Manifest V3 with a service worker (`background.js`) and content scripts (`content.js`).
- To iterate quickly: update files, then reload the extension from `chrome://extensions` (press the reload button).
- There is no build step — the extension runs directly from the folder.

Helpful files:
- `manifest.json` – extension metadata and permissions
- `popup.html`, `popup.js` – UI for quick searches
- `content.js` – highlights and tooltip injection
- `background.js` – service worker logic and context menu handling
- `history.html`, `history.js` – stored lookup history UI

## Contributing
- Open an issue for feature requests or bugs.
- Send PRs to the `main` branch; keep changes focused and add short descriptions.

## License
See the `LICENSE` file in this repository.

---
