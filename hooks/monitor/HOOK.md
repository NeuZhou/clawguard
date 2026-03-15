---
name: openclaw-watch-monitor
description: "Real-time monitoring for all OpenClaw agent activity"
metadata:
  openclaw:
    emoji: "👁️"
    events: ["message:received", "message:sent", "command:new", "command:reset", "session:compact:after"]
---

# OpenClaw Watch — Monitor Hook

Tracks all message traffic, session lifecycle, token usage estimates, and response times.
