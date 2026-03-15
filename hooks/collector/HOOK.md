# Collector Hook

Collects all agent activity for monitoring and analysis.

## Events

- `message:received` — Incoming messages
- `message:sent` — Outgoing messages  
- `message:preprocessed` — Preprocessed messages
- `command:new` — New session started
- `command:reset` — Session reset
- `command:stop` — Session stopped
- `session:compact:before` — Before context compaction
- `session:compact:after` — After context compaction
- `gateway:startup` — Gateway started

## Data Collected

- Messages with full metadata (direction, session, channel, tokens, cost)
- Response latency tracking
- Session lifecycle events
- Sub-agent spawn/complete detection
