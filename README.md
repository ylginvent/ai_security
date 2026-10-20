# AI Asset Gate

Security & governance intake for AI assets before they are published to the Azure AI product catalogue.

Teams submit their application (zip) and complete an intake questionnaire. The gate scans the code, dependencies, model artefacts and configuration, combines the results with the questionnaire answers and returns a decision:

| Decision | Meaning |
| --- | --- |
| **Approved for catalogue** | All gates pass. A reviewer signs off and publishes. |
| **Manual review required** | No blocking issues, but high findings, an EU AI Act high-risk use case or a trust score below 75. |
| **Blocked** | Exposed secrets, unsafe model files, critical findings or a prohibited AI practice. |

## What is checked

| Scanner | Based on |
| --- | --- |
| Secret detection | Gitleaks-derived rules (cloud keys, AI provider keys, tokens, private keys, connection strings) |
| Dependency vulnerabilities | [OSV.dev](https://osv.dev) for npm, PyPI, Maven, NuGet, Go and crates.io manifests and lockfiles |
| Static code analysis | Semgrep- and Bandit-derived rules (injection, deserialisation, TLS, XSS …) |
| AI / LLM security | OWASP Top 10 for LLM Applications 2025 (prompt injection, output handling, excessive agency, supply chain …) |
| Model artefacts | ModelScan-style pickle opcode analysis, Keras Lambda layers, NumPy object arrays |
| Configuration & IaC | Hadolint- and Checkov-derived rules for Dockerfiles, Terraform, Bicep, Kubernetes, GitHub Actions |
| Questionnaire | NIST AI RMF, ISO/IEC 42001, EU AI Act, GDPR, OWASP AI Exchange, MITRE ATLAS |

Outputs: an interactive report, a JSON report and a CycloneDX 1.5 SBOM. Reviewer approval, catalogue publication and an append-only audit trail are included.

## Stack

- Next.js 16 (App Router), React 19, Tailwind CSS 4, TypeScript
- Supabase: Postgres for submissions and audit events, private Storage bucket for uploads
- Vercel for hosting (region `fra1`)

## Setup

1. Create a Supabase project (EU region) and run [`supabase/migrations/0001_init.sql`](supabase/migrations/0001_init.sql) in the SQL editor.
2. Set the environment variables from [`.env.example`](.env.example) in Vercel (Project → Settings → Environment Variables):
   - `SUPABASE_URL`
   - `SUPABASE_PUBLISHABLE_KEY`, used only to upload files to a one-time signed URL
   - `SUPABASE_SECRET_KEY`, server-side only
3. Redeploy.

Without these variables the app runs in **demo mode**. Submissions are then kept in memory and are lost when the server instance restarts.

Local development: `npm install && npm run dev`.

## Security model

- Row Level Security is enabled on all tables, with no policies. Only the server, using the secret key, can read or write data.
- Uploads go straight from the browser to a private bucket through a single-use signed upload URL. The server then downloads and scans the file in memory. Uploaded code is never executed.
- Every answer is checked on the server against the questionnaire schema.
- Archive limits (entry count, uncompressed size, per-file size) protect against zip bombs.

## Limitations

This is a demo. The scanners are pattern-based reimplementations of open-source rulesets. They do not replace full runs of Semgrep, Trivy, Gitleaks or ModelScan, and they do not replace a penetration test. Authentication is not enabled yet.
