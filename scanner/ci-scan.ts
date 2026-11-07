// lib/scan/ci-scan.ts — pure core for the "Axiom Resilience Scan" GitHub
// Action wedge (research review GO 2026-11-01: Postiz Learning B, Module 17
// PLG wedge). Classifies candidate JSON files as automation workflows and
// runs the canonical deterministic leak detectors over them.
//
// Pure and IO-free: the runner (actions/resilience-scan/ci-scan.mjs) does the
// filesystem walk and hands this module a file list. Same input → same
// report, bit-for-bit (Module 20.9 discipline).

export interface CandidateFile {
  path: string;
  content: string; // raw file text
}

export interface ClassifiedWorkflow {
  path: string;
  engine: "n8n" | "make" | "unknown";
}

export interface CiScanFinding {
  path: string;
  engine: string;
  leakCode: string;
  severity: string;
  detail: string;
}

export interface CiScanReport {
  scanned_files: number;
  workflow_files: ClassifiedWorkflow[];
  findings: CiScanFinding[];
  /** The Module 17.3 upgrade card — printed by the runner on findings. */
  upgrade_card: string;
}

export const UPGRADE_CARD_TEXT =
  "Axiom Resilience Scan found revenue leaks in this repository's automation workflows. " +
  "Quantify the exposure in euros and approve governed fixes at https://axiomrevenuelabs.com — " +
  "free assessment, 2 minutes, deterministic findings with a full audit ledger.";

/** Identify automation-workflow JSON without guessing: structural markers only. */
export function classifyWorkflowJson(content: string): ClassifiedWorkflow | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  const obj = parsed as Record<string, unknown>;
  // n8n export: { nodes: [...], connections: {...} }
  if (Array.isArray(obj.nodes) && "connections" in obj) {
    return { path: "", engine: "n8n" };
  }
  // Make blueprint: { flow: [...] } (flow is an array of modules)
  if (Array.isArray(obj.flow)) {
    return { path: "", engine: "make" };
  }
  return null;
}

// ---------------------------------------------------------------------------
// n8n adapter (resilience-scan-v2, 2026-11-07). The canonical detectors read
// a normalised schema (loop.foreach / http.request / ci.run + `edges`). Real
// n8n exports use n8n node types and name-keyed `connections`, so v1 found
// nothing on them. This maps ONLY node types with an exact semantic match;
// everything else passes through untouched (no guessing).
// ---------------------------------------------------------------------------

const N8N_TYPE_MAP: Record<string, string> = {
  "n8n-nodes-base.splitInBatches": "loop.foreach",
  "n8n-nodes-base.httpRequest": "http.request",
  "n8n-nodes-base.executeCommand": "ci.run",
};

type N8nNode = {
  id?: unknown;
  name?: unknown;
  type?: unknown;
  typeVersion?: unknown;
  parameters?: Record<string, unknown>;
  config?: Record<string, unknown>;
  edges?: unknown;
};
type N8nConn = Record<string, { main?: ({ node?: unknown }[] | null)[] }>;

/** Pure: n8n export -> detector schema. Idempotent on already-normalised input. */
export function n8nToDetectorSchema(obj: { nodes: unknown[]; connections?: unknown }): {
  nodes: { id: string; type: string; config: Record<string, unknown>; edges: string[] }[];
} {
  const raw = obj.nodes.filter((n): n is N8nNode => typeof n === "object" && n !== null);
  const idOf = (n: N8nNode, i: number) => (typeof n.id === "string" ? n.id : `node_${i}`);
  // Connections are keyed by node NAME in real exports (by id in some fixtures).
  const keyToId = new Map<string, string>();
  raw.forEach((n, i) => {
    keyToId.set(idOf(n, i), idOf(n, i));
    if (typeof n.name === "string") keyToId.set(n.name, idOf(n, i));
  });
  const conns = (obj.connections && typeof obj.connections === "object" ? obj.connections : {}) as N8nConn;

  return {
    nodes: raw.map((n, i) => {
      const id = idOf(n, i);
      const srcType = typeof n.type === "string" ? n.type : "unknown";
      const type = N8N_TYPE_MAP[srcType] ?? srcType;
      const config: Record<string, unknown> = { ...(n.config ?? {}) };
      if (srcType === "n8n-nodes-base.executeCommand" && typeof n.parameters?.command === "string") {
        config.command = n.parameters.command;
      }
      const edges = new Set(Array.isArray(n.edges) ? n.edges.filter((e): e is string => typeof e === "string") : []);
      const key = typeof n.name === "string" && conns[n.name] ? n.name : id;
      const outputs = conns[key]?.main ?? [];
      // splitInBatches v3+: output 0 = "done", output 1 = loop body. Only the
      // loop body counts as "inside the loop"; earlier versions loop on 0.
      const loopV3 = srcType === "n8n-nodes-base.splitInBatches" && Number(n.typeVersion ?? 1) >= 3;
      outputs.forEach((targets, idx) => {
        if (loopV3 && idx !== 1) return;
        for (const t of targets ?? []) {
          const to = typeof t?.node === "string" ? keyToId.get(t.node) : undefined;
          if (to) edges.add(to);
        }
      });
      return { id, type, config, edges: [...edges] };
    }),
  };
}

/**
 * Scan a candidate file list. `detectLeaks` is injected so this core stays
 * import-free for testing; the runner passes the canonical detector.
 */
export async function scanCandidateFiles(
  files: CandidateFile[],
  detectLeaks: (workflowJson: unknown) => Promise<{
    findings: { leakCode: string; severity: string; nodeId?: string; description?: string }[];
  }>,
): Promise<CiScanReport> {
  const workflowFiles: ClassifiedWorkflow[] = [];
  const findings: CiScanFinding[] = [];

  for (const file of files) {
    const classified = classifyWorkflowJson(file.content);
    if (!classified) continue;
    workflowFiles.push({ path: file.path, engine: classified.engine });

    let parsed: unknown;
    try {
      parsed = JSON.parse(file.content);
    } catch {
      continue; // classify said JSON; a race/corruption here skips safely
    }
    const input = classified.engine === "n8n" ? n8nToDetectorSchema(parsed as { nodes: unknown[]; connections?: unknown }) : parsed;
    const report = await detectLeaks(input);
    for (const f of report.findings) {
      findings.push({
        path: file.path,
        engine: classified.engine,
        leakCode: f.leakCode,
        severity: f.severity,
        detail: f.description ?? `node ${f.nodeId ?? "unknown"}`,
      });
    }
  }

  return {
    scanned_files: files.length,
    workflow_files: workflowFiles,
    findings,
    upgrade_card: findings.length > 0 ? UPGRADE_CARD_TEXT : "",
  };
}
