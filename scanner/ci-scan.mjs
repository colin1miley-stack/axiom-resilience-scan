// actions/resilience-scan/ci-scan.mjs — runner for the "Axiom Resilience
// Scan" GitHub Action (Postiz Learning B wedge, Module 17.3 upgrade card).
// Self-contained apart from two TS files the composite action fetches from
// the Axiom repo at a pinned ref (Node 24 type-stripping runs TS directly —
// zero build step). Dogfooding inside the Axiom repo uses lib/scan directly.
//
// Usage: node ci-scan.mjs [--root <dir>] [--fail-on-findings true|false]
// Exit 0 = clean (or findings with fail-on-findings=false); 1 = findings;
// 2 = could not run (never silently passes).

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));

function arg(name, dflt) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : dflt;
}
const root = arg("root", process.cwd());
const failOnFindings = arg("fail-on-findings", "true") !== "false";

// Self-contained mode: ci-scan.ts + leak-detectors.ts fetched next to this
// runner. Dogfood mode: canonical lib/scan sources two levels up.
const here = process.cwd();
const repoRoot = resolve(scriptDir, "..", "..");
const libPath = existsSync(join(here, "ci-scan.ts"))
  ? join(here, "ci-scan.ts")
  : join(repoRoot, "lib", "scan", "ci-scan.ts");
const detectorsPath = existsSync(join(here, "leak-detectors.ts"))
  ? join(here, "leak-detectors.ts")
  : join(repoRoot, "lib", "scan", "leak-detectors.ts");

const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", "coverage", ".axiom-scan"]);

function* walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) yield* walk(join(dir, entry.name));
    } else if (entry.isFile() && entry.name.endsWith(".json")) {
      yield join(dir, entry.name);
    }
  }
}

const { scanCandidateFiles } = await import(pathToFileURL(libPath).href);
const { detectLeaks } = await import(pathToFileURL(detectorsPath).href);

let files;
try {
  files = [...walk(root)]
    .filter((p) => {
      try {
        return statSync(p).size <= 5 * 1024 * 1024;
      } catch {
        return false;
      }
    })
    .map((p) => ({ path: relative(root, p), content: readFileSync(p, "utf8") }));
} catch (err) {
  console.error(`::error ::resilience-scan could not walk ${root}: ${err && err.message ? err.message : String(err)}`);
  process.exit(2);
}

const report = await scanCandidateFiles(files, detectLeaks);

console.log(
  `Axiom Resilience Scan — ${report.scanned_files} JSON files, ` +
  `${report.workflow_files.length} automation workflows, ${report.findings.length} findings`,
);

for (const wf of report.workflow_files) {
  console.log(`workflow: ${wf.path} (${wf.engine})`);
}
for (const f of report.findings) {
  // GitHub Actions annotation format — surfaces in the PR files view.
  console.log(`::warning file=${f.path}::[${f.leakCode}/${f.severity}] ${f.detail}`);
}

if (report.findings.length > 0) {
  console.log("\n" + report.upgrade_card);
  if (failOnFindings) process.exit(1);
}
process.exit(0);
