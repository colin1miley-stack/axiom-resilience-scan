/**
 * Module 20.9 — Canonical leak detectors: COST-1 & SEC-5.
 *
 * MBD 20.9 (Deterministic AI): ALL detection here is strict, rule-based AST /
 * schema matching. ZERO speculative AI/LLM analysis is permitted in this
 * module. Same input JSON => same findings, bit-for-bit.
 *
 * COST-1 — Unoptimized API Call Pattern
 *   Detects unbatched loops feeding HTTP request nodes, producing redundant
 *   calls and margin erosion (MBD 1.10 context: pure waste, no AI spend).
 *
 * SEC-5 — CI/CD Secret Exfiltration Risk
 *   Detects base64/base32 encoding of env vars in CI steps (classic
 *   exfiltration obfuscation), producing exposed-key counts and breach cost.
 */

// ---------------------------------------------------------------------------
// Canonical leak type interfaces
// ---------------------------------------------------------------------------

export interface Cost1Leak {
  leakCode: "COST-1";
  severity: "high" | "medium";
  nodeId: string;
  /** Unbatched loop node feeding an HTTP request. */
  loopNodeId: string;
  /** Redundant HTTP calls estimated per month. */
  redundant_calls_per_month: number;
  /** HPI (Human Productivity Index) exposure in EUR from redundant calls. */
  estimated_hpi_exposure_eur: number;
  ruleId: "COST-1A" | "COST-1B";
  description: string;
}

export interface Sec5Leak {
  leakCode: "SEC-5";
  severity: "critical" | "high";
  ciStepId: string;
  /** Number of distinct secret-looking env vars being encoded. */
  exposed_key_count: number;
  /** Estimated breach cost in EUR (actuarial table, deterministic). */
  estimated_breach_cost_eur: number;
  encoding: "base64" | "base32";
  ruleId: "SEC-5A";
  description: string;
}

export type LeakFinding = Cost1Leak | Sec5Leak;

export interface LeakDetectionReport {
  findings: LeakFinding[];
  summary: {
    cost1Count: number;
    sec5Count: number;
    total_hpi_exposure_eur: number;
    total_breach_cost_eur: number;
  };
  /** SHA-256 over canonical findings JSON — deterministic audit anchor. */
  reportHash: string;
}

// ---------------------------------------------------------------------------
// Deterministic constants (actuarial tables — fixed in code, never inferred)
// ---------------------------------------------------------------------------

/** EUR cost per redundant API call per month (HPI table, MBD 1.10). */
const EUR_PER_REDUNDANT_CALL_MONTH = 0.42;

/** EUR per exposed secret key (actuarial breach cost table). */
const EUR_PER_EXPOSED_KEY = 120_000;

/** Max loop iterations considered "batched-safe" before COST-1 fires. */
const BATCH_THRESHOLD = 1;

const B64_RE = /base64|btoa|Buffer\.from\([^)]*['"]base64['"]\)/i;
const B32_RE = /base32/i;
const ENV_SECRET_RE = /\b(API[_-]?KEY|SECRET|TOKEN|PASSWORD|PRIVATE[_-]?KEY|AWS[_-]?(ACCESS[_-]?KEY|SECRET[_-]?KEY))\b/i;

// ---------------------------------------------------------------------------
// Normalization (strict schema matching — unknown shapes yield no findings)
// ---------------------------------------------------------------------------

interface NormalizedNode {
  id: string;
  type: string;
  config: Record<string, unknown>;
  edges: string[];
}

interface NormalizedWorkflow {
  nodes: NormalizedNode[];
  /** Adjacency: parent id -> child ids. */
  children: Map<string, string[]>;
  /** Reverse adjacency: child id -> parent ids. */
  parents: Map<string, string[]>;
}

function normalizeWorkflow(workflowJson: any): NormalizedWorkflow {
  const rawNodes: any[] = Array.isArray(workflowJson?.nodes) ? workflowJson.nodes : [];
  const nodes: NormalizedNode[] = rawNodes.map((n, i) => ({
    id: typeof n?.id === "string" ? n.id : `node_${i}`,
    type: typeof n?.type === "string" ? n.type : "unknown",
    config: n?.config && typeof n.config === "object" ? n.config : {},
    edges: Array.isArray(n?.edges) ? n.edges.filter((e: any) => typeof e === "string") : [],
  }));

  const children = new Map<string, string[]>();
  const parents = new Map<string, string[]>();
  for (const n of nodes) {
    children.set(n.id, n.edges);
    for (const e of n.edges) {
      const p = parents.get(e) ?? [];
      p.push(n.id);
      parents.set(e, p);
    }
  }
  return { nodes, children, parents };
}

function isLoopNode(node: NormalizedNode): boolean {
  return (
    node.type === "loop.foreach" ||
    node.type === "loop.while" ||
    (node.config.iterator != null && node.config.batch !== true)
  );
}

function isHttpNode(node: NormalizedNode): boolean {
  return node.type === "http.request";
}

// ---------------------------------------------------------------------------
// COST-1 detector (deterministic)
// ---------------------------------------------------------------------------

function detectCost1(wf: NormalizedWorkflow): Cost1Leak[] {
  const findings: Cost1Leak[] = [];
  const nodeById = new Map(wf.nodes.map((n) => [n.id, n]));

  for (const node of wf.nodes) {
    if (!isLoopNode(node)) continue;

    // Rule COST-1A: loop feeds an HTTP node with batch != true.
    const targets = (wf.children.get(node.id) ?? [])
      .map((id) => nodeById.get(id))
      .filter((t): t is NormalizedNode => !!t);

    for (const target of targets) {
      if (!isHttpNode(target)) continue;
      const batch = node.config.batch === true || target.config.batch === true;
      if (batch) continue; // batched — not a leak

      const iterations = num(node.config.iterations, 100);
      const callsPerRun = iterations; // one HTTP call per iteration, unbatched
      const runsPerMonth = num(node.config.runsPerMonth, 720); // default: 2x/hour
      const redundant = Math.max(0, callsPerRun - BATCH_THRESHOLD) * runsPerMonth;

      findings.push({
        leakCode: "COST-1",
        severity: redundant > 50_000 ? "high" : "medium",
        nodeId: target.id,
        loopNodeId: node.id,
        redundant_calls_per_month: redundant,
        estimated_hpi_exposure_eur: round2(redundant * EUR_PER_REDUNDANT_CALL_MONTH),
        ruleId: "COST-1A",
        description:
          `Unbatched loop "${node.id}" issues one HTTP call per iteration to "${target.id}" ` +
          `(${redundant.toLocaleString()} redundant calls/month).`,
      });
    }

    // Rule COST-1B: loop whose body has multiple HTTP children with no merge
    // (N parallel requests where 1 batched request would do).
    const httpChildren = targets.filter(isHttpNode);
    if (httpChildren.length > 1 && node.config.merge !== true) {
      const per = httpChildren.length - 1; // one request is legit
      const runsPerMonth = num(node.config.runsPerMonth, 720);
      const redundant = per * runsPerMonth;
      findings.push({
        leakCode: "COST-1",
        severity: "medium",
        nodeId: httpChildren[0].id,
        loopNodeId: node.id,
        redundant_calls_per_month: redundant,
        estimated_hpi_exposure_eur: round2(redundant * EUR_PER_REDUNDANT_CALL_MONTH),
        ruleId: "COST-1B",
        description:
          `Loop "${node.id}" fans out to ${httpChildren.length} HTTP nodes without merge; ` +
          `${per} redundant requests per run.`,
      });
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// SEC-5 detector (deterministic)
// ---------------------------------------------------------------------------

function detectSec5(wf: NormalizedWorkflow): Sec5Leak[] {
  const findings: Sec5Leak[] = [];

  for (const node of wf.nodes) {
    const isCiStep =
      node.type === "ci.step" ||
      node.type === "ci.run" ||
      node.type === "pipeline.step";
    if (!isCiStep) continue;

    const commands = Array.isArray(node.config.commands)
      ? (node.config.commands as unknown[]).filter((c): c is string => typeof c === "string")
      : typeof node.config.command === "string"
        ? [node.config.command as string]
        : [];

    for (const cmd of commands) {
      const encoding = B64_RE.test(cmd) ? "base64" : B32_RE.test(cmd) ? "base32" : null;
      if (!encoding) continue;

      // Strict match: encoded payload must reference a secret-like env var.
      const envRefs = (cmd.match(/\$\{?[A-Z0-9_]+\}?/g) ?? [])
        .map((m) => m.replace(/[${}]/g, ""))
        .filter((name) => ENV_SECRET_RE.test(name));

      if (envRefs.length === 0) continue;

      findings.push({
        leakCode: "SEC-5",
        severity: envRefs.length >= 3 ? "critical" : "high",
        ciStepId: node.id,
        exposed_key_count: envRefs.length,
        estimated_breach_cost_eur: envRefs.length * EUR_PER_EXPOSED_KEY,
        encoding,
        ruleId: "SEC-5A",
        description:
          `CI step "${node.id}" ${encoding}-encodes ${envRefs.length} secret-like env var(s): ` +
          envRefs.join(", ") + ".",
      });
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Deterministic, rule-based leak detection. No LLM, no randomness, no clocks
 * (except the report hash input which excludes timestamps by design).
 */
export async function detectLeaks(workflowJson: any): Promise<LeakDetectionReport> {
  const wf = normalizeWorkflow(workflowJson);
  const cost1 = detectCost1(wf);
  const sec5 = detectSec5(wf);
  const findings: LeakFinding[] = [...cost1, ...sec5];

  const canonical = JSON.stringify(
    findings,
    Object.keys(findings[0] ?? { leakCode: 1 }).length ? undefined : undefined
  );
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  const reportHash = Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return {
    findings,
    summary: {
      cost1Count: cost1.length,
      sec5Count: sec5.length,
      total_hpi_exposure_eur: round2(
        cost1.reduce((a, f) => a + f.estimated_hpi_exposure_eur, 0)
      ),
      total_breach_cost_eur: sec5.reduce((a, f) => a + f.estimated_breach_cost_eur, 0),
    },
    reportHash,
  };
}

function num(v: unknown, fallback: number): number {
  return typeof v === "number" && Number.isFinite(v) ? v : fallback;
}

function round2(v: number): number {
  return Math.round(v * 100) / 100;
}
