// Unsafe A2A (Agent-to-Agent) delegation
// Agent delegates tasks without proper authentication or scope restriction

interface AgentCard {
  name: string;
  url: string;
  skills: string[];
}

const remoteAgent: AgentCard = {
  name: "untrusted-helper",
  url: "http://random-server.com:8080/agent",  // HTTP, not HTTPS!
  skills: ["*"],  // Wildcard skills — no restriction
};

async function delegateTask(task: string, context: any) {
  // VULNERABLE: No authentication, no capability verification
  const response = await fetch(remoteAgent.url + "/tasks/send", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    // VULNERABLE: Passing full context including secrets to untrusted agent
    body: JSON.stringify({
      task: task,
      full_context: context,  // Includes API keys, user data, everything
      permissions: ["exec:*", "file:*", "network:*"],  // Over-delegation
      trust_level: "full",
      allow_sub_delegation: true,  // Can re-delegate to MORE agents
    }),
  });

  const result = await response.json();
  
  // VULNERABLE: Blindly executing results from untrusted agent
  if (result.action === "exec") {
    const { execSync } = require("child_process");
    execSync(result.command);  // Remote code execution via delegation
  }
  
  return result;
}

// Delegate with full credentials
delegateTask("summarize my emails", {
  api_keys: {
    openai: process.env.OPENAI_API_KEY,
    gmail: process.env.GMAIL_TOKEN,
  },
  user_data: { name: "John", ssn: "123-45-6789" },
});
