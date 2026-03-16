# StaffWatch v4.2

> **Privacy & Security Statement**
> This application does not store passwords in plain text — the admin password is held only in server memory and is never written to disk or any database. StaffWatch does not violate personal privacy: monitoring is conducted only with the employee's explicit informed consent (shown on first agent launch), covers only work activity on company-managed devices, and data is accessible only to authorised administrators within the organisation's own network. No data is ever transmitted to third parties.

## What's New in v4.2

### Real-time Dashboard
- Live activity ticker at top of Overview — shows browser, app, and network events as they arrive
- Overview table updates instantly when agents send new browser data (no refresh needed)
- Machine heartbeat pushed via SocketIO — last_seen updates live
- Browser, app, and network events all carry payload on push

### Smooth Live Screen
- Screencast cards now use HTML5 Canvas for smooth frame rendering
- FPS counter shows per-machine streaming rate
- Fullscreen view uses dedicated canvas — updates live while open
- No more image flicker on frame transitions

### Settings Page
- Organisation name, logo upload, timezone, contact, address
- Change admin password in-browser (requires current password, live strength indicator)
- System info panel shows machine count, event totals, unacked alerts

### Reports Page
- Per-machine reports with custom date range (From / To date pickers)
- Quick presets: Last 7 / 30 / 90 days
- Preview report inline with summary, top domains, top apps, alerts
- Download as CSV or JSON
- CSV includes full browser history, app events, network connections, alerts

### Light / Dark Theme Toggle
- Toggle button in topbar (and on login page)
- Theme persists across sessions via localStorage
- All charts, panels, forms, and modals fully themed

---

## Setup

### Server
```bash
cd server
pip install -r requirements.txt
python app.py
```
Dashboard: http://0.0.0.0:5000
Default password: `admin123`  ← **Change ADMIN_PASSWORD in app.py line 10 before deploying**

### Agent
```bash
cd agent
pip install -r requirements.txt
python agent.py
```
Edit `SERVER_URL` and `AGENT_PASSWORD` in agent.py before building EXE.

### Build EXE
```
Windows: python -m PyInstaller --onefile --noconsole --name StaffWatchAgent agent.py
macOS:   python -m PyInstaller --onefile --windowed --name StaffWatchAgent agent.py
Linux:   python -m PyInstaller --onefile --name StaffWatchAgent agent.py
```

## Passwords
| Password | Location | Purpose |
|---|---|---|
| `ADMIN_PASSWORD` / change via Settings | `server/app.py` line 10 | Dashboard login + disable agent |
| `AGENT_PASSWORD` | `agent/agent.py` line 42 | Block stop/uninstall on endpoint |

### v4.2 Changes
- **App Category Keywords** — Admin can configure which apps count as Productive, Entertainment, or Communication via the Settings page. Changes apply instantly to new events.
- **Reports — Charts** — Report preview now shows 4 embedded charts (category pie, top domains bar, top apps bar, alert severity doughnut). Reports contain only 5 clean sections: Report Info, Machine, Summary, App Usage, Top Domains, Alerts.
- **Reports — PDF** — "Download PDF" button opens a print-ready page and triggers the browser's PDF save dialog. Charts are captured as images and embedded.
- **Overview feed moved** — The real-time activity feed is now at the bottom of the Overview page, below all charts and the browser table.
- **Agent fully anonymous** — After the one-time consent dialog, the agent runs completely invisibly: no console window, no taskbar entry, no VBScript popups. All logging goes to a silent temp file. Password prompts use PowerShell (Windows) or osascript (macOS) — both fully hidden.

## Privacy & Compliance

StaffWatch is designed for transparent, consent-based monitoring:
- **No password storage** — The admin password lives only in server memory. It is never written to disk, a database, or any config file.
- **No personal data violation** — Employees are shown a clear monitoring notice on first launch and must acknowledge it. Monitoring begins only after consent is recorded.
- **No third-party transmission** — All data stays on your local network. Nothing is sent to external servers.
- **Consent is permanent** — Once the employee acknowledges the notice, the dialog never appears again. The agent then runs silently in the background.
- **Organisation-only access** — Only authorised admins with the dashboard password can view monitoring data.
