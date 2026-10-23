# AI Asset Gate

Security & governance intake for AI assets before they are published to the Azure AI product catalogue.

Teams submit their application (zip) and complete an intake questionnaire. The gate scans the code, dependencies, model artefacts and configuration, combines the results with the questionnaire answers and returns a decision:

| Decision | Meaning |
| --- | --- |
| **Approved for catalogue** | All gates pass. A reviewer signs off and publishes. |
| **Manual review required** | No blocking issues, but high findings, an EU AI Act high-risk use case, a trust score below 75, an incomplete scan (a scanner failed or timed out, files were skipped) or serious findings waived via `.aigateignore`. |
| **Blocked** | Exposed secrets, unsafe model files, critical findings, a prohibited AI practice, or an upload with nothing scannable. |

## What is checked

| Scanner | Based on |
| --- | --- |
| Secret detection | Gitleaks-derived rules (cloud keys, AI provider keys, tokens, private keys, connection strings) |
| Dependency vulnerabilities | [OSV.dev](https://osv.dev) for npm, PyPI, Maven, NuGet, Go and crates.io manifests and lockfiles |
| Static code analysis | Semgrep- and Bandit-derived rules (injection, deserialisation, TLS, XSS …) |
| AI / LLM security | OWASP Top 10 for LLM Applications 2025 (prompt injection, output handling, excessive agency, supply chain …) |
| Model artefacts | ModelScan-style pickle opcode analysis, Keras Lambda layers, NumPy object arrays |
| Configuration & IaC | Hadolint- and Checkov-derived rules for Dockerfiles, Terraform, Bicep, Kubernetes, GitHub Actions |
| Agent skill review | Agent Skills format and best practices: structure, quality and security of `SKILL.md`, reference files and scripts, with improvement suggestions |
| Licences & deprecation | [deps.dev](https://deps.dev) (Open Source Insights): copyleft, missing licences and deprecated packages |
| Answers vs. code | Flags intake answers that contradict the scan, such as "no external AI" when the code calls a public LLM API |
| Questionnaire | NIST AI RMF, ISO/IEC 42001, EU AI Act, GDPR, OWASP AI Exchange, MITRE ATLAS |

There are two intake paths:

- **AI application or model:** six questionnaire sections.
- **Agent skill:** ownership details only, followed by the skill review.

You can provide the code in three ways: upload a zip, link a public GitHub or GitLab repository, or use the built-in demo.

Outputs: an interactive report, a JSON report and a CycloneDX 1.5 SBOM. Reviewer approval, catalogue publication and an append-only audit trail are included.

**Where it sits.** The gate is a layer in front of the upload to the Azure AI catalogue database, not a separate portal. Asset owners only see the questionnaire, the upload and their report; the overview page is an optional admin and reviewer console.

**Grouped findings.** Repeats of the same rule are shown as one card with the number of hits, one shared explanation and one shared fix, with the individual places listed inside (toggle "Combine repeats", or group by issue type).

**New versions.** "Submit a new version" on a report opens the wizard with the previous answers filled in (and the version number bumped). The new report links to the previous one and shows what was fixed, what is new and what is still open, plus the score change. Matching ignores shifting line numbers: findings are paired on rule and file, then on line, code excerpt or title.

## Stack

- Next.js 16 (App Router), React 19, Tailwind CSS 4, TypeScript
- Supabase: Postgres for submissions and audit events, private Storage bucket for uploads
- Vercel for hosting (region `fra1`)

## Setup

1. Create a Supabase project (EU region) and run the migrations in order in the SQL editor:
   - [`supabase/migrations/0001_init.sql`](supabase/migrations/0001_init.sql)
   - [`supabase/migrations/0002_hardening.sql`](supabase/migrations/0002_hardening.sql): append-only audit trail, idempotency key, database checks on review status. If its unique index on `file_path` fails, an old upload was submitted twice; delete the duplicate row first.
   - [`supabase/migrations/0003_versions.sql`](supabase/migrations/0003_versions.sql): links a new version to the previous one (`previous_id`). Without it the comparison still works, but an old report does not point to its newer version.
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
