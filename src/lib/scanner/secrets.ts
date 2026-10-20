import type { Severity } from "../types";
import { splitLines, snippetOf, type Archive, type RawFinding, type ScannerResult } from "./archive";

/**
 * Secret detection. Regels afgeleid van de Gitleaks-ruleset (gitleaks.toml), aangevuld met
 * Azure-specifieke patronen. Werkt per regel; de gevonden waarde wordt nooit volledig opgeslagen.
 */

interface SecretRule {
  id: string;
  title: string;
  severity: Severity;
  /** Patroon zonder g-flag; `group` wijst de geheime waarde aan. */
  pattern: RegExp;
  group?: number;
  /** AI-provider sleutel: extra referentie naar OWASP LLM02. */
  ai?: boolean;
  /** Wat de credential mogelijk maakt. */
  impact: string;
  /** Wat er geroteerd moet worden. */
  rotate: string;
  /** True = vals positief, negeren. */
  ignore?: (value: string, match: RegExpMatchArray) => boolean;
  /** Niet maskeren (bijv. PEM-header bevat zelf geen geheim). */
  noRedact?: boolean;
  generic?: boolean;
}

const PLACEHOLDER =
  /^(?:x+|\*+|\.+|-+|_+|0+)$|change[_-]?me|example|placeholder|dummy|sample|redacted|replace[_-]?me|insert[_-]?|your[_-]?|my[_-]?(?:api|secret|token|key|password)|todo|fixme|xxxx|\*\*\*|^<.*>$|\$\{|\{\{|%\(|^\$[A-Za-z_(]|^(?:true|false|null|none|undefined|password|passwd|secret|token|pass|test|admin|root|guest|default)$/i;

export function isPlaceholder(value: string): boolean {
  return PLACEHOLDER.test(value.trim());
}

export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  freq.forEach((n) => {
    const p = n / s.length;
    h -= p * Math.log2(p);
  });
  return h;
}

export function mask(value: string): string {
  const visible = value.slice(0, 4);
  return visible + "*".repeat(Math.max(4, Math.min(16, value.length - 4)));
}

/** Sleutelnamen die op "token/key/secret" lijken maar geen geheim bevatten (tokenizer, key_vault_name …). */
const NON_SECRET_KEY =
  /tokeni[sz]er|max_?tokens?|tokens?_?(?:count|limit|len|length|url|uri|endpoint|type|path|file|usage|budget)|(?:secret|key|token|password)_?(?:name|id|ref|path|file|url|uri|field|label|prompt|hint|policy|length|len|version|env|var|header|type|vault)\b|key_?vault|public_?key|primary_?key_?column|sort_?key|partition_?key|foreign_?key|row_?key/i;

const RULES: SecretRule[] = [
  {
    id: "aws-access-key-id",
    title: "AWS access key ID",
    severity: "critical",
    pattern: /\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b/,
    impact: "An AWS access key ID grants programmatic access to the AWS account it belongs to when combined with its secret key, which is usually stored nearby.",
    rotate: "Deactivate and delete the access key in AWS IAM",
    ignore: (v) => /EXAMPLE$/.test(v),
  },
  {
    id: "aws-secret-access-key",
    title: "AWS secret access key",
    severity: "critical",
    pattern: /(?:aws_?secret_?access_?key|aws_?secret_?key|secret_?access_?key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/i,
    impact: "An AWS secret access key, together with its key ID, gives full programmatic access with the permissions of the IAM principal.",
    rotate: "Deactivate the key pair in AWS IAM and issue a new one",
  },
  {
    id: "azure-storage-connection-string",
    title: "Azure Storage account key in connection string",
    severity: "critical",
    pattern: /AccountName=([^;\s"']+);\s*AccountKey=([A-Za-z0-9+/]{20,}={0,2})/i,
    group: 2,
    impact: "A storage account key grants full read, write and delete access to every container, queue, table and file share in the storage account.",
    rotate: "Rotate both storage account access keys in the Azure portal",
    ignore: (_v, m) => (m[1] ?? "").toLowerCase() === "devstoreaccount1",
  },
  {
    id: "azure-ad-client-secret",
    title: "Microsoft Entra ID (Azure AD) client secret",
    severity: "critical",
    pattern: /(?:^|[^A-Za-z0-9_~.-])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?![A-Za-z0-9_~.-])/,
    impact: "An Entra ID client secret lets anyone authenticate as the app registration and obtain tokens for every API it has been granted.",
    rotate: "Delete the client secret from the app registration (Certificates & secrets) and create a new one",
  },
  {
    id: "azure-openai-key",
    title: "Azure OpenAI / Azure AI services key",
    severity: "critical",
    pattern: /(?:(?:azure|openai|aoai|cognitive|ocp-apim-subscription)[\w-]{0,40}?key|["']api-key["'])["']?\s*[:=]\s*["']?([a-fA-F0-9]{32})\b/i,
    ai: true,
    impact: "An Azure OpenAI / Azure AI services key allows anyone to call the deployment, consume quota at Capgemini's expense and read prompts and completions routed through it.",
    rotate: "Regenerate Key 1 and Key 2 on the Azure AI resource (Keys and Endpoint)",
  },
  {
    id: "openai-api-key",
    title: "OpenAI API key",
    severity: "critical",
    pattern: /\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}|sk-[A-Za-z0-9]{48})(?![A-Za-z0-9_-])/,
    ai: true,
    impact: "An OpenAI API key lets anyone call the OpenAI API on the owner's billing account and access stored files, assistants and fine-tuned models.",
    rotate: "Revoke the key at platform.openai.com",
  },
  {
    id: "anthropic-api-key",
    title: "Anthropic API key",
    severity: "critical",
    pattern: /\b(sk-ant-[a-z0-9]{2,10}-[A-Za-z0-9_-]{32,})/,
    ai: true,
    impact: "An Anthropic API key lets anyone call the Claude API on the owner's account.",
    rotate: "Revoke the key in the Anthropic Console",
  },
  {
    id: "huggingface-token",
    title: "Hugging Face access token",
    severity: "high",
    pattern: /\b(hf_[A-Za-z0-9]{30,40})\b/,
    ai: true,
    impact: "A Hugging Face token can read private models and datasets and, with write scope, push tampered model weights to the organisation's repositories.",
    rotate: "Invalidate the token under Settings → Access Tokens on huggingface.co",
  },
  {
    id: "google-api-key",
    title: "Google API key",
    severity: "high",
    pattern: /\b(AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])/,
    impact: "A Google API key allows calls to every Google Cloud API enabled for the project (including Gemini), billed to the owner.",
    rotate: "Delete or regenerate the key in Google Cloud Console → APIs & Services → Credentials",
  },
  {
    id: "github-token",
    title: "GitHub token",
    severity: "critical",
    pattern: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,100})\b/,
    impact: "A GitHub token gives access to repositories (and possibly organisation settings and CI secrets) with the scopes of its owner.",
    rotate: "Revoke the token in GitHub → Settings → Developer settings",
  },
  {
    id: "slack-token",
    title: "Slack token",
    severity: "high",
    pattern: /\b(xox[baprs]-[0-9A-Za-z]{8,}-[0-9A-Za-z-]{8,})/,
    impact: "A Slack token can read channels and post messages as the bot or user it belongs to.",
    rotate: "Revoke the token in the Slack app configuration",
  },
  {
    id: "stripe-live-key",
    title: "Stripe live secret key",
    severity: "critical",
    pattern: /\b((?:sk|rk)_live_[0-9A-Za-z]{20,})\b/,
    impact: "A Stripe live secret key can create charges, issue refunds and read customer payment data.",
    rotate: "Roll the key in the Stripe Dashboard → Developers → API keys",
  },
  {
    id: "private-key",
    title: "Private key",
    severity: "critical",
    pattern: /-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----/,
    noRedact: true,
    impact: "A committed private key compromises every system, certificate or signature that trusts the corresponding public key.",
    rotate: "Replace the key pair, revoke any certificate issued for it and remove the public key from authorised systems",
  },
  {
    id: "jwt",
    title: "JSON Web Token",
    severity: "medium",
    pattern: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})/,
    impact: "A hard-coded JWT may still be valid and grant access to the API that issued it; long-lived tokens are especially risky.",
    rotate: "Invalidate the token at the issuer (or rotate the signing key)",
  },
  {
    id: "database-url-password",
    title: "Database connection string with embedded password",
    severity: "high",
    pattern: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver):\/\/([^:\s/@"'<>]+):([^@\s/"'<>]+)@[^\s"'<>]+/i,
    group: 2,
    impact: "The connection string contains a database password, giving direct access to the data store and bypassing the application's access controls.",
    rotate: "Change the database user's password",
    ignore: (v) => isPlaceholder(v) || /^(?:pass(?:word)?|pwd|changeme|example|secret)$/i.test(v),
  },
  {
    id: "generic-secret",
    title: "Hard-coded secret",
    severity: "medium",
    pattern: /\b([A-Za-z0-9_.-]{0,40}(?:api[_-]?key|apikey|secret|token|passwd|password|pwd|access[_-]?key|auth[_-]?key|client[_-]?secret|private[_-]?key)[A-Za-z0-9_.-]{0,40})["']?\s*(?:[:=]|:=|=>)\s*["'`]([^"'`\s]{12,})["'`]/i,
    group: 2,
    generic: true,
    impact: "A credential-like value with high randomness is assigned to a secret-named variable.",
    rotate: "Rotate the credential at the issuing service",
    ignore: (v, m) => genericIgnored(m[1] ?? "", v),
  },
  {
    id: "generic-secret",
    title: "Hard-coded secret",
    severity: "medium",
    // .env / properties-stijl zonder quotes
    pattern: /^\s*(?:export\s+)?([A-Z0-9_]{0,40}(?:API_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|ACCESS_?KEY|AUTH_?KEY)[A-Z0-9_]{0,40})\s*=\s*([^\s"'#]{12,})\s*$/,
    group: 2,
    generic: true,
    impact: "A credential-like value with high randomness is assigned to a secret-named variable.",
    rotate: "Rotate the credential at the issuing service",
    ignore: (v, m) => genericIgnored(m[1] ?? "", v),
  },
];

function genericIgnored(key: string, value: string): boolean {
  if (NON_SECRET_KEY.test(key)) return true;
  if (isPlaceholder(value)) return true;
  if (/^https?:\/\//i.test(value) || /^[A-Z][A-Z0-9_]+$/.test(value)) return true;
  if (/^[a-z]+(?:[-_.][a-z]+)*$/.test(value)) return true; // gewone woorden / model-namen
  if (/process\.env|os\.environ|getenv|secretKeyRef|keyvault/i.test(value)) return true;
  return value.length < 12 || shannonEntropy(value) < 3.5;
}

const SKIP_GENERIC = /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Pipfile\.lock|Cargo\.lock|composer\.lock|go\.sum|uv\.lock|pdm\.lock|packages\.lock\.json)$|\.min\.(?:js|css)$|\.map$|\.svg$/i;

interface Compiled {
  rule: SecretRule;
  line: RegExp;
  pre: RegExp;
}

const COMPILED: Compiled[] = RULES.map((rule) => ({
  rule,
  line: new RegExp(rule.pattern.source, rule.pattern.flags.replace("g", "") + "g"),
  // Generieke regel: goedkope keyword-check i.p.v. de volledige regex over het hele bestand
  pre: rule.generic
    ? /api[_-]?key|apikey|secret|token|passw|pwd|access[_-]?key|auth[_-]?key|private[_-]?key/i
    : new RegExp(rule.pattern.source, rule.pattern.flags.replace("g", "").replace("m", "") + "m"),
}));

const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const MAX_PER_RULE = 50;
const MAX_LINE = 20000;

interface Hit {
  rule: SecretRule;
  value: string;
  key?: string;
}

export function scanSecrets(archive: Archive): ScannerResult {
  const findings: RawFinding[] = [];
  const perRule = new Map<string, number>();

  for (const file of archive.files) {
    if (file.text === undefined || file.text === "") continue;
    const skipGeneric = SKIP_GENERIC.test(file.path);
    const active = COMPILED.filter((c) => !(skipGeneric && c.rule.generic) && c.pre.test(file.text ?? ""));
    if (!active.length) continue;

    const lines = splitLines(file.text);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length < 8 || line.length > MAX_LINE) continue;
      const hits: Hit[] = [];
      for (const c of active) {
        if (c.rule.generic && line.length > 500) continue; // lange regels: geen generieke regel (backtracking)
        for (const m of line.matchAll(c.line)) {
          const value = m[c.rule.group ?? 1] ?? m[0];
          if (c.rule.ignore && c.rule.ignore(value, m)) continue;
          hits.push({ rule: c.rule, value, key: c.rule.generic ? m[1] : undefined });
          break;
        }
      }
      if (!hits.length) continue;

      // Per regel de meest ernstige/specifieke hit (regels staan van specifiek naar generiek)
      let best = hits[0];
      for (const h of hits) if (SEVERITY_RANK[h.rule.severity] > SEVERITY_RANK[best.rule.severity]) best = h;
      const count = (perRule.get(best.rule.id) ?? 0) + 1;
      perRule.set(best.rule.id, count);
      if (count > MAX_PER_RULE) continue;

      let redacted = line;
      for (const h of hits) if (!h.rule.noRedact) redacted = redacted.split(h.value).join(mask(h.value));
      const shown = best.rule.noRedact ? best.value : mask(best.value);
      const r = best.rule;
      findings.push({
        scanner: "secrets",
        ruleId: r.id,
        severity: r.severity,
        title: r.generic && best.key ? `${r.title} assigned to ${best.key}` : `${r.title} committed in source`,
        description: `${r.impact} Detected value: \`${shown}\`. Secrets committed to a repository stay in its history after deletion and are routinely harvested by automated scanners${r.ai ? "; a leaked AI provider key also exposes every prompt and completion sent with it" : ""}.`,
        remediation: `${r.rotate} and treat the old value as compromised. Remove it from the code and the Git history (git filter-repo or BFG), then load it at runtime from Azure Key Vault — or, preferably, use a managed identity so no secret is needed at all.`,
        refs: r.ai ? ["CWE-798", "OWASP LLM02:2025"] : ["CWE-798"],
        file: file.path,
        line: i + 1,
        snippet: snippetOf(redacted),
      });
    }
  }

  return { findings };
}
