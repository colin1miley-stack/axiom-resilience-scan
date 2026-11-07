# Axiom Resilience Scan

Deterministic revenue-leak scanning for **n8n workflow exports** in your CI.
Findings show up as pull-request annotations.

- **Runs locally.** The scanner is vendored in this action and hash-verified before it runs. It makes no network calls, and your workflow JSON never leaves the runner.
- **Deterministic.** The rules are fixed and contain no LLM. The same input always gives the same findings.
- **Apache-2.0.** Read it, fork it, audit it.

## Quick start

```yaml
# .github/workflows/axiom-resilience-scan.yml
name: Axiom Resilience Scan
on: [pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: colin1miley-stack/axiom-resilience-scan@v1
        with:
          path: workflows            # where your n8n exports live (default ".")
          fail-on-findings: "true"   # "false" = annotate only
```

If you use n8n source control, point `path` at the folder n8n syncs to. That's `workflows/` by default.

## What it detects

| Rule | What it means | Why it costs money |
|---|---|---|
| **COST-1** | A loop (`Loop Over Items` / `splitInBatches`) feeds an HTTP Request node with one call per item and no batching | Redundant API calls: usage bills, rate-limit failures, slower syncs |
| **SEC-5** | An Execute Command step base64/base32-encodes secret-looking env vars (`API_KEY`, `SECRET`, `TOKEN`, …) | The classic pattern for slipping credentials out through logs or outbound calls |

Only node types with an exact semantic match are mapped. Everything else is ignored rather than guessed at.

Try it on the bundled mock:

```bash
cd scanner && node ci-scan.mjs --root ../examples --fail-on-findings false
# ::warning file=lead-sync.mock.json::[COST-1/high] Unbatched loop "s1" issues one HTTP call per iteration to "h1" ...
```

`examples/lead-sync.mock.json` is a fabricated workflow. It contains no client data.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Directory to scan, relative to the workspace |
| `fail-on-findings` | `true` | Exit 1, which fails the check, when leaks are found |

Exit codes: `0` means clean, `1` means findings, `2` means the scan could not run. A failed run never passes silently.

## Scope and honesty notes

- This repository contains **two open rules** (COST-1, SEC-5). It does not contain the Axiom commercial rubric (AXR), which covers resilience, PII, brand-safety and inline-credential rules with euro valuation.
- Make blueprints are recognised, but module-level detection in this action covers n8n only.
- The euro and call-volume figures in findings come from fixed defaults in `scanner/leak-detectors.ts`. When your workflow doesn't state iterations or schedule, the defaults apply. Treat these figures as order-of-magnitude, not an invoice.
- The scanner reads workflow structure only. It does not execute workflows or contact their endpoints.

## Going further

On findings, the log prints a link to the free Axiom assessment at https://axiomrevenuelabs.com. It's optional and nothing is sent automatically.

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
