#!/usr/bin/env tsx
// ClawGuard Benchmark Runner
// Runs ClawGuard scan on each sample and reports detection rates

import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";

interface Expectation {
  expectedRules: string[];
  minFindings: number;
  description: string;
}

interface Expected {
  description: string;
  expectations: Record<string, Expectation>;
}

interface Finding {
  ruleId: string;
  severity: string;
  description: string;
  category: string;
}

interface ScanResult {
  file: string;
  findings: Finding[];
  expectedRules: string[];
  matchedRules: string[];
  missedRules: string[];
  pass: boolean;
}

function runBenchmark(): void {
  const benchDir = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Z]:)/, "$1"));
  const samplesDir = path.join(benchDir, "samples");
  const expectedPath = path.join(benchDir, "expected.json");
  const clawguardBin = path.join(benchDir, "..", "dist", "src", "cli.js");

  if (!fs.existsSync(clawguardBin)) {
    console.error("❌ ClawGuard not built. Run 'npm run build' first.");
    process.exit(1);
  }

  const expected: Expected = JSON.parse(fs.readFileSync(expectedPath, "utf8"));
  const results: ScanResult[] = [];

  let totalExpected = 0;
  let totalMatched = 0;
  let totalFindings = 0;
  let filesWithFindings = 0;

  console.log("🛡️  ClawGuard Detection Benchmark\n");
  console.log("=".repeat(60));

  for (const [file, expectation] of Object.entries(expected.expectations)) {
    const filePath = path.join(samplesDir, file);
    if (!fs.existsSync(filePath)) {
      console.log(`⚠️  Missing sample: ${file}`);
      continue;
    }

    let findings: Finding[] = [];
    try {
      const output = execSync(
        `node "${clawguardBin}" scan "${filePath}" --format json`,
        { encoding: "utf8", timeout: 30000, stdio: ["pipe", "pipe", "pipe"] }
      );
      const parsed = JSON.parse(output);
      findings = Array.isArray(parsed) ? parsed : parsed.findings || [];
    } catch (err: any) {
      // --strict exits with code 1 on findings, but still outputs JSON on stdout
      if (err.stdout) {
        try {
          const parsed = JSON.parse(err.stdout);
          findings = Array.isArray(parsed) ? parsed : parsed.findings || [];
        } catch {}
      }
    }

    const foundRuleIds = [...new Set(findings.map((f) => f.ruleId))];
    const matchedRules = expectation.expectedRules.filter((r) => foundRuleIds.includes(r));
    const missedRules = expectation.expectedRules.filter((r) => !foundRuleIds.includes(r));
    const pass = matchedRules.length > 0 && findings.length >= expectation.minFindings;

    totalExpected += expectation.expectedRules.length;
    totalMatched += matchedRules.length;
    totalFindings += findings.length;
    if (findings.length > 0) filesWithFindings++;

    results.push({ file, findings, expectedRules: expectation.expectedRules, matchedRules, missedRules, pass });

    const icon = pass ? "✅" : "❌";
    console.log(`\n${icon} ${file}`);
    console.log(`   Findings: ${findings.length} | Matched rules: ${matchedRules.join(", ") || "none"}`);
    if (missedRules.length > 0) {
      console.log(`   Missed: ${missedRules.join(", ")}`);
    }
  }

  // Summary
  const totalFiles = Object.keys(expected.expectations).length;
  const passedFiles = results.filter((r) => r.pass).length;
  const ruleDetectionRate = totalExpected > 0 ? ((totalMatched / totalExpected) * 100).toFixed(1) : "0";
  const fileDetectionRate = ((filesWithFindings / totalFiles) * 100).toFixed(1);

  console.log("\n" + "=".repeat(60));
  console.log("\n📊 BENCHMARK RESULTS\n");

  // Markdown table
  console.log("| Sample | Findings | Expected Rules | Matched | Status |");
  console.log("|--------|----------|---------------|---------|--------|");
  for (const r of results) {
    const status = r.pass ? "✅ PASS" : "❌ FAIL";
    console.log(
      `| ${r.file} | ${r.findings.length} | ${r.expectedRules.join(", ")} | ${r.matchedRules.join(", ") || "—"} | ${status} |`
    );
  }

  console.log(`\n**File detection rate:** ${fileDetectionRate}% (${filesWithFindings}/${totalFiles} files)`);
  console.log(`**Rule detection rate:** ${ruleDetectionRate}% (${totalMatched}/${totalExpected} expected rules matched)`);
  console.log(`**Total findings:** ${totalFindings}`);
  console.log(`**Files passed:** ${passedFiles}/${totalFiles}`);

  // Exit code
  const overallRate = parseFloat(fileDetectionRate);
  if (overallRate < 80) {
    console.log("\n⚠️  Detection rate below 80% threshold!");
    process.exit(1);
  } else {
    console.log(`\n🎉 Detection rate: ${fileDetectionRate}% — benchmark passed!`);
  }
}

runBenchmark();
