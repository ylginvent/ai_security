import { Buffer } from "node:buffer";
import type { Severity } from "../types";
import { splitLines, snippetOf, type Archive, type RawFinding, type ScannerResult } from "./archive";

/**
 * Secret detection. Regels afgeleid van de Gitleaks-ruleset (gitleaks.toml), aangevuld met
 * Azure-, Supabase- en AI-provider-specifieke patronen. Werkt per regel; de gevonden waarde wordt
 * nooit volledig opgeslagen (beschrijving en snippet zijn gemaskeerd).
 */

interface SecretRule {
  id: string;
  title: string;
  severity: Severity;
  /** Patroon zonder g-flag; `group` wijst de geheime waarde aan (standaard: eerste gematchte group). */
  pattern: RegExp;
  group?: number;
  /** AI-provider sleutel: extra referentie naar OWASP LLM02. */
  ai?: boolean;
  /** Wat de credential mogelijk maakt. */
  impact: string;
  /** Wat er geroteerd moet worden. */
  rotate: string;
  /** Naam van de omgevingsvariabele in het voorbeeld in de remediation. */
  env?: string;
  /** True = vals positief, negeren. `next` is de volgende regel van het bestand. */
  ignore?: (value: string, match: RegExpMatchArray, next: string) => boolean;
  /** Lagere severity in een herkenbare minder ernstige situatie (lokale dev-database, versleutelde sleutel). */
  soften?: (value: string, match: RegExpMatchArray) => { severity: Severity; reason: string } | null;
  /** Niet maskeren (bijv. PEM-header bevat zelf geen geheim). */
  noRedact?: boolean;
  /** Geen nep-sleutel-check: wachtwoorden hoeven niet willekeurig te zijn; JWT's worden al gevalideerd via de payload. */
  weakAllowed?: boolean;
  generic?: boolean;
}

const PLACEHOLDER =
  /^(?:x+|\*+|\.+|-+|_+|0+)$|change[_-]?me|example|placeholder|dummy|sample|redacted|replace[_-]?me|insert[_-]?|your[_-]?|my[_-]?(?:api|secret|token|key|password)|todo|fixme|xxxx|\*\*\*|lorem|\.\.\.|<[^>]*>|\$\{|\{\{|%\(|^\$[A-Za-z_(]|^\{[\w.]*\}$|^%[A-Za-z_]+%$|#\{|@Microsoft\.KeyVault|^(?:true|false|null|none|undefined|password|passwd|secret|token|pass|test|admin|root|guest|default)$/i;

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

/** Maskeert een geheim: korte waarden helemaal, langere tonen alleen een herkenbaar begin. */
export function mask(value: string): string {
  const visible = value.length >= 20 ? 4 : value.length >= 12 ? 2 : 0;
  return value.slice(0, visible) + "*".repeat(Math.max(4, Math.min(16, value.length - visible)));
}

/** Kenmerken van nep- of voorbeeldsleutels in documentatie en tests ("sk-xxxx…", "AKIA…EXAMPLE", "ghp_000…"). */
const FAKE_MARKER = /(.)\1{5,}|example|sample|dummy|placeholder|redacted|your[_-]?(?:api|key|token|secret)|0123456|123456789|abcdefgh|<|>|\.\.\./i;

function looksFake(value: string): boolean {
  if (FAKE_MARKER.test(value)) return true;
  // prefix ("sk-proj-", "ghp_", "xoxb-") niet meetellen voor de entropie
  const body = value.replace(/^[A-Za-z]{2,6}[_-](?:[A-Za-z0-9]{2,8}[_-])?/, "");
  return body.length >= 16 && shannonEntropy(body) < 3;
}

/** Payload van een JWT, of null als het geen geldige JSON is. */
function jwtPayload(token: string): Record<string, unknown> | null {
  const part = token.split(".")[1];
  if (!part) return null;
  try {
    const json = Buffer.from(part.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    const value: unknown = JSON.parse(json);
    return value && typeof value === "object" ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Host die op een lokale of container-netwerk database wijst (localhost, db, postgres, host.docker.internal …). */
const LOCAL_HOST = /^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal|[A-Za-z][\w-]*)$/i;

function localCredential(value: string, m: RegExpMatchArray): { severity: Severity; reason: string } | null {
  const host = m[3] ?? "";
  if (!LOCAL_HOST.test(host)) return null;
  return {
    severity: "low",
    reason: `The host (${host}) is a local or container-network address, so this is most likely a development default rather than a production password. Still move it to configuration so a real password never ends up here.`,
  };
}

/** PEM-header met daadwerkelijk sleutelmateriaal erachter (op dezelfde regel als "\n…" of op de volgende regel). */
function pemHasBody(m: RegExpMatchArray, next: string): boolean {
  const rest = (m.input ?? "").slice((m.index ?? 0) + m[0].length);
  if (/^(?:\\r)?\\n[A-Za-z0-9+/=]{40,}/.test(rest)) return true;
  // header staat alleen (eventueel gevolgd door \n", quote, komma of +): kijk naar de volgende regel
  if (!/^(?:\\r)?(?:\\n)?["'\x60]?\s*[,+]?\s*$/.test(rest)) return false;
  const body = next.trim().replace(/^["'\x60]/, "");
  return /^(?:[A-Za-z0-9+/=]{40,}|Proc-Type:|Comment:)/.test(body);
}

const AZURE_EMULATOR_KEYS = new Set([
  // Azurite / Storage Emulator en Cosmos DB Emulator: publiek gedocumenteerde, vaste sleutels
  "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==",
  "C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==",
]);

/** Sleutelnamen die op "token/key/secret" lijken maar geen geheim bevatten (tokenizer, key_vault_name …). */
const NON_SECRET_KEY =
  /tokeni[sz]er|max_?tokens?|tokens?_?(?:count|limit|len|length|url|uri|endpoint|type|path|file|usage|budget)|(?:secret|key|token|password)_?(?:name|id|ref|path|file|url|uri|field|label|prompt|hint|policy|length|len|version|env|var|header|type|vault)\b|key_?vault|public_?key|primary_?key_?column|sort_?key|partition_?key|foreign_?key|row_?key|(?:next|prev|page|continuation|cursor|sync|cancel(?:lation)?)_?token|csrf|xsrf/i;

const SUPABASE_JWT = /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})/;

const RULES: SecretRule[] = [
  {
    id: "aws-access-key-id",
    title: "AWS access key ID",
    severity: "critical",
    pattern: /\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b/,
    impact: "An AWS access key ID grants programmatic access to the AWS account it belongs to when combined with its secret key, which is usually stored nearby.",
    rotate: "Deactivate and delete the access key in AWS IAM",
    env: "AWS_ACCESS_KEY_ID",
  },
  {
    id: "aws-secret-access-key",
    title: "AWS secret access key",
    severity: "critical",
    pattern: /(?:aws_?secret_?access_?key|aws_?secret_?key|secret_?access_?key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/i,
    impact: "An AWS secret access key, together with its key ID, gives full programmatic access with the permissions of the IAM user or role.",
    rotate: "Deactivate the key pair in AWS IAM and issue a new one",
    env: "AWS_SECRET_ACCESS_KEY",
  },
  {
    id: "azure-storage-connection-string",
    title: "Azure Storage / Cosmos DB account key in connection string",
    severity: "critical",
    pattern: /(?:AccountName=([^;\s"']+)|AccountEndpoint=([^;\s"']+));\s*AccountKey=([A-Za-z0-9+/]{20,}={0,2})/i,
    group: 3,
    impact: "An account key grants full read, write and delete access to all data in the storage account (every container, queue, table and file share) or Cosmos DB account.",
    rotate: "Rotate both account keys in the Azure portal (Access keys / Keys)",
    env: "AZURE_STORAGE_CONNECTION_STRING",
    ignore: (v, m) =>
      AZURE_EMULATOR_KEYS.has(v) || (m[1] ?? "").toLowerCase() === "devstoreaccount1" || /\/\/(?:localhost|127\.0\.0\.1)\b/i.test(m[2] ?? ""),
  },
  {
    id: "azure-shared-access-key",
    title: "Azure Service Bus / Event Hubs / SignalR access key",
    severity: "critical",
    pattern: /\b(?:SharedAccessKey|AccessKey)=([A-Za-z0-9+/]{30,}={0,2})/,
    impact: "A shared access key in a connection string lets anyone send, receive or manage messages on the namespace (Service Bus, Event Hubs, IoT Hub or SignalR) with the rights of that policy.",
    rotate: "Regenerate the primary and secondary key of the shared access policy in the Azure portal",
    env: "SERVICEBUS_CONNECTION_STRING",
    ignore: (v) => AZURE_EMULATOR_KEYS.has(v),
  },
  {
    id: "azure-sas-token",
    title: "Azure shared access signature (SAS) token",
    severity: "high",
    pattern: /[?&]sig=([A-Za-z0-9%+/]{30,}(?:%3D|=){0,2})/i,
    impact: "A SAS URL grants whoever holds it the listed permissions on the storage resource until it expires, without any further authentication.",
    rotate: "Revoke the SAS by rotating the account key it was signed with (or delete the stored access policy) and issue short-lived user-delegation SAS tokens at runtime",
    env: "BLOB_SAS_URL",
    ignore: (_v, m) => !/[?&](?:sv|se|sp|sr|spr)=/i.test(m.input ?? ""),
  },
  {
    id: "azure-ad-client-secret",
    title: "Microsoft Entra ID (Azure AD) client secret",
    severity: "critical",
    pattern: /(?:^|[^A-Za-z0-9_~.-])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?![A-Za-z0-9_~.-])/,
    impact: "An Entra ID client secret lets anyone authenticate as the app registration and obtain tokens for every API it has been granted.",
    rotate: "Delete the client secret from the app registration (Certificates & secrets) and create a new one",
    env: "AZURE_CLIENT_SECRET",
  },
  {
    id: "azure-openai-key",
    title: "Azure OpenAI / Azure AI services key",
    severity: "critical",
    pattern: /(?:(?:azure|openai|aoai|cognitive|ocp-apim-subscription)[\w-]{0,40}?key|["']api-key["'])["']?\s*[:=]\s*["']?([a-fA-F0-9]{32}|[A-Za-z0-9]{84})(?![A-Za-z0-9])/i,
    ai: true,
    impact: "An Azure OpenAI / Azure AI services key allows anyone to call the deployment, consume quota at Capgemini's expense and read prompts and completions routed through it.",
    rotate: "Regenerate Key 1 and Key 2 on the Azure AI resource (Keys and Endpoint)",
    env: "AZURE_OPENAI_API_KEY",
  },
  {
    id: "openai-api-key",
    title: "OpenAI API key",
    severity: "critical",
    pattern: /\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}|sk-[A-Za-z0-9]{48})(?![A-Za-z0-9_-])/,
    ai: true,
    impact: "An OpenAI API key lets anyone call the OpenAI API on the owner's billing account and access stored files, assistants and fine-tuned models.",
    rotate: "Revoke the key at platform.openai.com (API keys)",
    env: "OPENAI_API_KEY",
  },
  {
    id: "anthropic-api-key",
    title: "Anthropic API key",
    severity: "critical",
    pattern: /\b(sk-ant-[a-z0-9]{2,10}-[A-Za-z0-9_-]{32,})/,
    ai: true,
    impact: "An Anthropic API key lets anyone call the Claude API on the owner's account.",
    rotate: "Revoke the key in the Anthropic Console (API keys)",
    env: "ANTHROPIC_API_KEY",
  },
  {
    id: "openrouter-api-key",
    title: "OpenRouter API key",
    severity: "critical",
    pattern: /\b(sk-or-v1-[a-f0-9]{64})\b/,
    ai: true,
    impact: "An OpenRouter key lets anyone call every model available through OpenRouter on the owner's credit.",
    rotate: "Delete the key at openrouter.ai (Keys)",
    env: "OPENROUTER_API_KEY",
  },
  {
    id: "ai-provider-key",
    title: "AI provider API key",
    severity: "high",
    // Groq, xAI, Perplexity, Replicate, LangSmith, Pinecone
    pattern: /\b(gsk_[A-Za-z0-9]{52}|xai-[A-Za-z0-9]{80}|pplx-[A-Za-z0-9]{48}|r8_[A-Za-z0-9]{37}|lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}|pcsk_[A-Za-z0-9_]{40,})(?![A-Za-z0-9_-])/,
    ai: true,
    impact: "An AI platform key (Groq, xAI, Perplexity, Replicate, LangSmith or Pinecone) lets anyone use the service on the owner's account; for LangSmith and Pinecone it also exposes stored traces (full prompts and answers) or the vector index with your documents.",
    rotate: "Revoke the key in the provider's dashboard",
    env: "PROVIDER_API_KEY",
  },
  {
    id: "huggingface-token",
    title: "Hugging Face access token",
    severity: "high",
    pattern: /\b(hf_[A-Za-z0-9]{30,40})\b/,
    ai: true,
    impact: "A Hugging Face token can read private models and datasets and, with write scope, push tampered model weights to the organisation's repositories.",
    rotate: "Invalidate the token under Settings → Access Tokens on huggingface.co",
    env: "HF_TOKEN",
  },
  {
    id: "databricks-token",
    title: "Databricks personal access token",
    severity: "high",
    pattern: /\b(dapi[a-f0-9]{32}(?:-\d)?)\b/,
    ai: true,
    impact: "A Databricks token gives access to the workspace with the owner's permissions: notebooks, clusters, model serving endpoints and data in Unity Catalog.",
    rotate: "Revoke the token in Databricks → User Settings → Developer → Access tokens",
    env: "DATABRICKS_TOKEN",
  },
  {
    id: "google-api-key",
    title: "Google API key",
    severity: "high",
    pattern: /\b(AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])/,
    impact: "A Google API key can call every Google Cloud API enabled for the project — including Gemini — billed to the owner. Firebase web keys are meant to be public, but without API restrictions they can also be used for those other APIs.",
    rotate: "Regenerate the key in Google Cloud Console → APIs & Services → Credentials and add API and application (HTTP referrer / IP) restrictions",
    env: "GOOGLE_API_KEY",
  },
  {
    id: "github-token",
    title: "GitHub token",
    severity: "critical",
    pattern: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,100})\b/,
    impact: "A GitHub token gives access to repositories (and possibly organisation settings and CI secrets) with the scopes of its owner.",
    rotate: "Revoke the token in GitHub → Settings → Developer settings",
    env: "GITHUB_TOKEN",
  },
  {
    id: "gitlab-token",
    title: "GitLab personal access token",
    severity: "critical",
    pattern: /\b(glpat-[A-Za-z0-9_-]{20,})/,
    impact: "A GitLab token gives access to repositories, CI/CD variables and the API with the scopes of its owner.",
    rotate: "Revoke the token in GitLab → Preferences → Access tokens",
    env: "GITLAB_TOKEN",
  },
  {
    id: "package-registry-token",
    title: "npm / PyPI publish token",
    severity: "high",
    pattern: /\b(npm_[A-Za-z0-9]{36}|pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})(?![A-Za-z0-9_-])/,
    impact: "A package registry token can publish new versions of the owner's packages — a direct supply-chain attack on everyone who installs them.",
    rotate: "Revoke the token on npmjs.com (Access Tokens) or pypi.org (Account settings → API tokens)",
    env: "NPM_TOKEN",
  },
  {
    id: "slack-token",
    title: "Slack token",
    severity: "high",
    pattern: /\b(xox[baprs]-[0-9A-Za-z]{8,}-[0-9A-Za-z-]{8,})/,
    impact: "A Slack token can read channels and post messages as the bot or user it belongs to.",
    rotate: "Revoke the token in the Slack app configuration",
    env: "SLACK_BOT_TOKEN",
  },
  {
    id: "chat-webhook",
    title: "Slack / Teams / Discord webhook URL",
    severity: "medium",
    pattern: /https:\/\/(?:hooks\.slack\.com\/(?:services|workflows|triggers)\/([A-Za-z0-9+/_-]{20,})|[\w.-]+\.webhook\.office\.com\/webhookb2\/([^\s"'<>]{20,})|(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/([\w-]{30,}))/,
    impact: "Anyone with an incoming-webhook URL can post messages into the channel, for example convincing phishing messages that appear to come from your app.",
    rotate: "Delete the webhook / connector in Slack, Teams or Discord and create a new one",
    env: "WEBHOOK_URL",
  },
  {
    id: "telegram-bot-token",
    title: "Telegram bot token",
    severity: "high",
    pattern: /\b(\d{8,10}:AA[A-Za-z0-9_-]{33})(?![A-Za-z0-9_-])/,
    impact: "A Telegram bot token gives full control over the bot: reading every message sent to it and sending messages as the bot.",
    rotate: "Revoke the token with @BotFather (/revoke)",
    env: "TELEGRAM_BOT_TOKEN",
  },
  {
    id: "stripe-live-key",
    title: "Stripe live secret key",
    severity: "critical",
    pattern: /\b((?:sk|rk)_live_[0-9A-Za-z]{20,})\b/,
    impact: "A Stripe live secret key can create charges, issue refunds and read customer payment data.",
    rotate: "Roll the key in the Stripe Dashboard → Developers → API keys",
    env: "STRIPE_SECRET_KEY",
  },
  {
    id: "sendgrid-api-key",
    title: "SendGrid API key",
    severity: "high",
    pattern: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])/,
    impact: "A SendGrid key can send e-mail from your verified domains — ideal for phishing that passes SPF/DKIM checks.",
    rotate: "Delete the key in SendGrid → Settings → API Keys",
    env: "SENDGRID_API_KEY",
  },
  {
    id: "private-key",
    title: "Private key",
    severity: "critical",
    pattern: /-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----/,
    noRedact: true,
    impact: "A committed private key compromises every system, certificate or signature that trusts the corresponding public key.",
    rotate: "Replace the key pair, revoke any certificate issued for it and remove the public key from every system that trusts it",
    env: "PRIVATE_KEY_PATH",
    // Alleen een header (bijv. in een parser of voorbeeld) zonder sleutelmateriaal is geen lek
    ignore: (_v, m, next) => !pemHasBody(m, next),
    soften: (v) =>
      v.startsWith("ENCRYPTED")
        ? { severity: "medium", reason: "The key is encrypted with a passphrase, which slows down misuse but does not prevent offline guessing." }
        : null,
  },
  {
    id: "supabase-service-role-key",
    title: "Supabase service_role key",
    severity: "critical",
    pattern: SUPABASE_JWT,
    impact: "The Supabase service_role key bypasses Row Level Security: anyone holding it can read, change and delete every row in the database and every file in Storage.",
    rotate: "Roll the JWT secret / service_role key in Supabase → Project Settings → API (or migrate to the new sb_secret_ keys and revoke the legacy ones)",
    env: "SUPABASE_SERVICE_ROLE_KEY",
    weakAllowed: true,
    ignore: (v) => jwtPayload(v)?.role !== "service_role",
  },
  {
    id: "supabase-secret-key",
    title: "Supabase secret API key",
    severity: "critical",
    pattern: /\b(sb_secret_[A-Za-z0-9_-]{20,})/,
    impact: "A Supabase secret key bypasses Row Level Security and gives full access to the project's database and Storage.",
    rotate: "Delete the secret key in Supabase → Project Settings → API Keys and create a new one",
    env: "SUPABASE_SECRET_KEY",
  },
  {
    id: "jwt",
    title: "JSON Web Token",
    severity: "medium",
    pattern: SUPABASE_JWT,
    impact: "A hard-coded JWT may still be valid and grant access to the API that issued it; long-lived tokens are especially risky.",
    rotate: "Invalidate the token at the issuer (or rotate the signing key)",
    env: "ACCESS_TOKEN",
    weakAllowed: true,
    ignore: (v) => {
      const p = jwtPayload(v);
      if (!p) return true; // geen JSON-payload: geen echte JWT
      // Supabase anon key is publiek bedoeld; service_role heeft een eigen regel; jwt.io-voorbeeldtoken
      return p.role === "anon" || p.role === "service_role" || (p.sub === "1234567890" && p.name === "John Doe");
    },
  },
  {
    id: "database-url-password",
    title: "Database connection string with embedded password",
    severity: "high",
    pattern: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver):\/\/([^:\s/@"'<>]+):([^@\s/"'<>]+)@([^\s"'<>/:?#,;]+)/i,
    group: 2,
    weakAllowed: true,
    impact: "The connection string contains a database password, giving direct access to the data store and bypassing the application's access controls.",
    rotate: "Change the database user's password",
    env: "DATABASE_URL",
    ignore: (v) => isPlaceholder(v) || /^(?:pass(?:word)?|pwd|changeme|example|secret)$/i.test(v),
    soften: localCredential,
  },
  {
    id: "url-credentials",
    title: "Password embedded in a URL",
    severity: "high",
    pattern: /\bhttps?:\/\/([^:\s/@"'<>]+):([^@\s/"'<>]{3,})@([^\s"'<>/:?#,;]+)/i,
    group: 2,
    weakAllowed: true,
    impact: "The URL contains a user name and password (or token) for the service it points to; anyone who sees the code, a log line or a browser history entry can reuse them.",
    rotate: "Change the password or revoke the token for that account",
    env: "SERVICE_PASSWORD",
    ignore: (v, m) => isPlaceholder(v) || isPlaceholder(m[1] ?? "") || /(?:^|\.)example\.(?:com|org|net)$/i.test(m[3] ?? ""),
    soften: localCredential,
  },
  {
    id: "generic-secret",
    title: "Hard-coded secret",
    severity: "medium",
    pattern: /\b([A-Za-z0-9_.-]{0,40}(?:api[_-]?key|apikey|secret|token|passwd|password|pwd|access[_-]?key|auth[_-]?key|client[_-]?secret|private[_-]?key)[A-Za-z0-9_.-]{0,40})["']?\s*(?:[:=]|:=|=>)\s*["'`]([^"'`\s]{12,})["'`]/i,
    group: 2,
    generic: true,
    impact: "A credential-like value with high randomness is assigned to a variable whose name suggests a secret.",
    rotate: "Rotate the credential at the service that issued it",
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
    impact: "A credential-like value with high randomness is assigned to a variable whose name suggests a secret.",
    rotate: "Rotate the credential at the service that issued it",
    ignore: (v, m) => genericIgnored(m[1] ?? "", v),
  },
];

function genericIgnored(key: string, value: string): boolean {
  if (NON_SECRET_KEY.test(key)) return true;
  if (isPlaceholder(value)) return true;
  if (/^https?:\/\//i.test(value) || /^[A-Z][A-Z0-9_]+$/.test(value)) return true;
  if (/^[a-z]+(?:[-_.][a-z]+)*$/.test(value)) return true; // gewone woorden / model-namen
  if (/^(?:[A-Z][a-z]+){2,}$|^[a-z]+(?:[A-Z][a-z]+)+$/.test(value)) return true; // CamelCase-namen (i18n-sleutels, klassen)
  if (/process\.env|os\.environ|getenv|secretKeyRef|keyvault/i.test(value)) return true;
  if (/[()]/.test(value)) return true; // functieaanroep, geen letterlijke waarde
  if (/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(value)) return true; // settings.API_KEY
  if (/^(?:\.{1,2}\/|~\/|[A-Za-z]:[\\/]|\/[a-z_][\w.-]*\/)/.test(value) || /\.(?:json|pem|key|crt|cer|txt|ya?ml|env|cfg|ini|p12|pfx)$/i.test(value)) {
    return true; // pad naar een bestand
  }
  return value.length < 12 || shannonEntropy(value) < 3.5;
}

const SKIP_GENERIC = /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Pipfile\.lock|Cargo\.lock|composer\.lock|go\.sum|uv\.lock|pdm\.lock|packages\.lock\.json)$|\.lock$|\.min\.(?:js|css)$|\.map$|\.svg$|\.snap$/i;

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
/** Generieke regels alleen op normale regels (backtracking, minified code). Specifieke regels: elke lengte. */
const MAX_GENERIC_LINE = 500;
const SNIPPET = 160;

interface Hit {
  rule: SecretRule;
  value: string;
  key?: string;
  /** Positie en einde van de volledige match in de regel. */
  index: number;
  end: number;
  /** Positie van de geheime waarde zelf in de regel. */
  valueAt: number;
  severity: Severity;
  note?: string;
}

/** Venster van max. 160 tekens rond positie `at`, zodat de treffer ook in lange (minified) regels zichtbaar is. */
function around(text: string, at: number): string {
  const t = text.trim();
  if (t.length <= SNIPPET) return t;
  const offset = text.length - text.trimStart().length;
  const start = Math.max(0, Math.min(at - offset - 40, t.length - (SNIPPET - 2)));
  const body = t.slice(start, start + SNIPPET - 2);
  return `${start > 0 ? "…" : ""}${body}${start + SNIPPET - 2 < t.length ? "…" : ""}`;
}

function envName(hit: Hit): string {
  if (hit.rule.env) return hit.rule.env;
  const fromKey = (hit.key ?? "").replace(/[^A-Za-z0-9]+/g, "_").replace(/^_+|_+$/g, "").toUpperCase();
  return fromKey || "MY_SECRET";
}

export function scanSecrets(archive: Archive): ScannerResult {
  const findings: RawFinding[] = [];
  const perRule = new Map<string, number>();

  for (const file of archive.files) {
    const text = file.text;
    if (text === undefined || text === "") continue;
    const skipGeneric = SKIP_GENERIC.test(file.path);
    const active = COMPILED.filter((c) => !(skipGeneric && c.rule.generic) && c.pre.test(text));
    if (!active.length) continue;

    const lines = splitLines(text);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length < 8) continue;
      const next = lines[i + 1] ?? "";
      const hits: Hit[] = [];
      for (const c of active) {
        const r = c.rule;
        if (r.generic && line.length > MAX_GENERIC_LINE) continue;
        for (const m of line.matchAll(c.line)) {
          // expliciete group, anders de eerste capture group die gematcht heeft (alternatieven met eigen groups)
          const value = (r.group ? m[r.group] : m.slice(1).find((g) => g !== undefined)) ?? m[0];
          if (!value) continue;
          if (r.ignore && r.ignore(value, m, next)) continue;
          if (!r.generic && !r.noRedact && !r.weakAllowed && looksFake(value)) continue;
          const soft = r.soften ? r.soften(value, m) : null;
          const index = m.index ?? 0;
          const rel = m[0].lastIndexOf(value);
          hits.push({
            rule: r,
            value,
            key: r.generic ? m[1] : undefined,
            index,
            end: index + m[0].length,
            valueAt: rel >= 0 ? index + rel : index,
            severity: soft ? soft.severity : r.severity,
            note: soft ? soft.reason : undefined,
          });
          break;
        }
      }
      if (!hits.length) continue;

      // Per regel de meest ernstige/specifieke hit (regels staan van specifiek naar generiek)
      let best = hits[0];
      for (const h of hits) if (SEVERITY_RANK[h.severity] > SEVERITY_RANK[best.severity]) best = h;
      const count = (perRule.get(best.rule.id) ?? 0) + 1;
      perRule.set(best.rule.id, count);
      if (count > MAX_PER_RULE) continue;

      // Snippet maskeren: PEM-header behouden maar alles erachter weglaten; gevonden waarden op hun positie
      // maskeren (niet via zoeken/vervangen: "postgres:postgres@" zou dan ook het schema maskeren)
      const pem = hits.find((h) => h.rule.noRedact);
      const cut = pem && pem.end < line.length ? pem.end : line.length;
      let redacted = line.slice(0, cut);
      let applied = cut;
      const spans = hits
        .filter((h) => !h.rule.noRedact && h.valueAt + h.value.length <= cut)
        .sort((a, b) => b.valueAt - a.valueAt);
      for (const h of spans) {
        if (h.valueAt + h.value.length > applied) continue; // overlapt met een al gemaskeerde waarde
        redacted = redacted.slice(0, h.valueAt) + mask(h.value) + redacted.slice(h.valueAt + h.value.length);
        applied = h.valueAt;
      }
      // dezelfde (willekeurige) sleutel kan vaker op de regel staan
      for (const h of hits) {
        if (!h.rule.noRedact && !h.rule.weakAllowed && h.value.length >= 12) redacted = redacted.split(h.value).join(mask(h.value));
      }
      if (cut < line.length) redacted += " … [key material redacted]";
      const shown = best.rule.noRedact ? best.value : mask(best.value);
      const at = best.rule.noRedact ? best.index : best.valueAt;

      const r = best.rule;
      const env = envName(best);
      const local = best.severity === "low";
      findings.push({
        scanner: "secrets",
        ruleId: r.id,
        severity: best.severity,
        title: r.generic && best.key ? `${r.title} assigned to ${best.key}` : `${r.title} committed in source`,
        description: [
          `${r.impact} Detected value (masked): \`${shown}\`.`,
          best.note ?? "",
          local
            ? ""
            : `Anyone with access to this code — or to a copy, fork, backup or build artefact of it — can use the credential. Secrets also stay in Git history after deletion and are harvested by automated scanners within minutes of a public push${r.ai ? "; a leaked AI provider key also exposes every prompt and completion sent with it" : ""}.`,
        ]
          .filter(Boolean)
          .join(" "),
        remediation: [
          `1. ${r.rotate}${local ? "" : " — treat the old value as compromised, even if the repository is private"}.`,
          `2. Remove the value from the code and read it at runtime instead, e.g. os.environ["${env}"] (Python) or process.env.${env} (Node.js), with the value stored in Azure Key Vault or the App Service / Container Apps settings. Better still, use a managed identity so no secret is needed at all.`,
          "3. If the code is in Git, purge the value from the history (git filter-repo or BFG) and force-push.",
          r.generic
            ? "Not a real credential (test value, revoked key)? Replace it with an obvious placeholder such as \"<your-api-key>\" or an environment variable reference — the scan ignores those."
            : "",
        ]
          .filter(Boolean)
          .join("\n"),
        refs: r.ai ? ["CWE-798", "OWASP LLM02:2025"] : ["CWE-798"],
        file: file.path,
        line: i + 1,
        snippet: snippetOf(around(redacted, at)),
      });
    }
  }

  return { findings };
}
