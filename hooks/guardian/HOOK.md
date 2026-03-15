# Guardian Hook

Smart alerts and auto-control for cost, security, and health.

## Events

- `message:received` — Check budgets, detect anomalies
- `message:sent` — Track costs, check budgets
- `command:new` — Session tracking

## Features

- Cost budgets with configurable thresholds (80%/90%/100%)
- Security finding escalation for critical/high severity
- Stuck agent detection (no activity timeout)
- Alert cooldown to prevent storms
