# Dashboard Guide

## Access

Default: **http://localhost:19790**

## Tabs

### Overview
- Health status (healthy / warnings / critical)
- Active sessions count
- Today's cost and security alerts
- 24-hour activity sparkline

### Monitor
- Real-time message feed via Server-Sent Events (SSE)
- Filter by session or channel
- Message direction indicators (inbound/outbound)

### Security
- Security score (0-100, deducted by findings)
- OWASP coverage map
- Rule enable/disable toggles
- Recent findings with evidence

### Cost
- Daily / weekly / monthly breakdown
- Per-model and per-session costs
- Budget status bars
- Monthly projection

### Audit
- Hash chain event log
- Chain verification status
- JSON/CSV export

### Settings
- Budget configuration
- Alert thresholds
- Exporter toggles (JSONL, syslog, webhook)
- Rule management

## REST API

| Endpoint | Method | Description |
|---|---|---|
| `/api/overview` | GET | Dashboard stats |
| `/api/messages` | GET | Messages (query: `limit`, `offset`, `session`) |
| `/api/sessions` | GET | Session list |
| `/api/security` | GET | Security findings |
| `/api/security/score` | GET | Score + rule statuses |
| `/api/cost` | GET | Cost breakdown |
| `/api/audit` | GET | Audit log |
| `/api/audit/verify` | GET | Hash chain verification |
| `/api/rules/toggle` | POST | Toggle rule (body: `{id, enabled}`) |
| `/api/config` | GET/POST | Read/update config |
| `/api/stream` | GET | SSE event stream |
| `/api/export/:format` | GET | Export (json/csv) |
