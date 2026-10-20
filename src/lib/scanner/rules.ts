import type { ScannerId, Severity } from "../types";
import type { SourceFile } from "./archive";

/**
 * Regelgebaseerde code-analyse. SAST-regels zijn afgeleid van Semgrep (p/python, p/javascript)
 * en Bandit; AI-regels volgen de OWASP Top 10 for LLM Applications 2025.
 * `{match}` in titel/omschrijving wordt vervangen door de eerste capture group.
 */
export interface Rule {
  id: string;
  scanner: ScannerId;
  severity: Severity;
  title: string;
  description: string;
  remediation: string;
  refs: string[];
  extensions: string[];
  pattern: RegExp;
  /** Regel wordt overgeslagen als deze regex op dezelfde regel matcht. */
  unless?: RegExp;
  /** Extra bestandsfilter naast de extensies. */
  appliesTo?: (f: SourceFile) => boolean;
  /** Waarden na password/secret/key in de snippet maskeren. */
  maskSnippet?: boolean;
}

export const PY = [".py", ".pyi", ".ipynb"];
export const JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"];
const CODE = [...PY, ...JS];

/* ------------------------------------------------------- LLM-output als sink */

/** Variabelen die doorgaans modeloutput bevatten. */
const LLM_VALUE = String.raw`(?:completion|response|resp|reply|answer|generated(?:_\w+)?|llm_\w+|\w+_(?:completion|response|reply)|ai_\w+|model_output|output_text|chain\.(?:run|invoke|predict)|agent\.(?:run|invoke)|llm\.(?:invoke|predict|call))\b`;
const SINK = String.raw`(?:(?:^|[^\w.])(?:eval|exec)|\bos\.(?:system|popen)|\bsubprocess\.\w+|\.(?:execute|executemany|executescript|exec_driver_sql)|\bexecSync|\bchild_process\.exec|\bnew\s+Function)`;

/** Code-uitvoerende of SQL-sink waarvan het eerste argument modeloutput is. */
export const LLM_SINK = new RegExp(
  String.raw`${SINK}\s*\(\s*(?:f["'][^"'\n]*\{\s*|\x60[^\x60]*\$\{\s*)?(?:(?:self|this)\.)?${LLM_VALUE}`,
);

/* ------------------------------------------------------------------------ SAST */

export const SAST_RULES: Rule[] = [
  // Python
  {
    id: "py-eval-exec",
    scanner: "sast",
    severity: "high",
    title: "Dynamic code execution with {match}()",
    description: "eval()/exec() executes arbitrary Python. If any part of the argument can be influenced by a user, a document or a model response, this is remote code execution in the application's context.",
    remediation: "Remove eval/exec. Parse data with json.loads or ast.literal_eval, and use explicit dispatch tables instead of evaluating code strings.",
    refs: ["CWE-95", "Bandit B307", "Semgrep python.lang.security.audit.eval-detected"],
    extensions: PY,
    pattern: /(?:^|[^\w.])(eval|exec)\s*\(/,
    unless: LLM_SINK,
  },
  {
    id: "py-insecure-deserialization",
    scanner: "sast",
    severity: "high",
    title: "Insecure deserialisation ({match})",
    description: "pickle-based deserialisation (pickle, dill, joblib, cloudpickle, pandas.read_pickle, numpy allow_pickle) executes code embedded in the data. Loading a file or payload from an untrusted source is equivalent to running an attacker's program.",
    remediation: "Only unpickle data you produced and integrity-protect it (HMAC/signature). For data exchange use JSON, Parquet or safetensors; for scikit-learn models consider skops or ONNX.",
    refs: ["CWE-502", "Bandit B301", "OWASP LLM03:2025"],
    extensions: PY,
    pattern: /\b((?:pickle|cPickle|_pickle|dill|joblib|cloudpickle)\.loads?|pd\.read_pickle|pandas\.read_pickle)\s*\(|\b(np\.load|numpy\.load)\s*\([^)\n]*allow_pickle\s*=\s*True/,
  },
  {
    id: "py-yaml-unsafe-load",
    scanner: "sast",
    severity: "medium",
    title: "Unsafe YAML deserialisation",
    description: "yaml.load() without SafeLoader can instantiate arbitrary Python objects (e.g. !!python/object/apply:os.system), leading to code execution when the YAML comes from a user, a repository or a model.",
    remediation: "Use yaml.safe_load() or pass Loader=yaml.SafeLoader.",
    refs: ["CWE-502", "Bandit B506"],
    extensions: PY,
    pattern: /\byaml\.(?:unsafe_load|load|load_all)\s*\(/,
    unless: /Loader\s*=\s*(?:yaml\.)?(?:SafeLoader|CSafeLoader|BaseLoader)\b/,
  },
  {
    id: "py-subprocess-shell",
    scanner: "sast",
    severity: "high",
    title: "Subprocess call with shell=True",
    description: "With shell=True the command line is interpreted by /bin/sh, so any interpolated value (file names, user input, model output) can inject additional commands.",
    remediation: "Pass the command as a list of arguments with shell=False (the default), and validate or allow-list any variable parts.",
    refs: ["CWE-78", "Bandit B602"],
    extensions: PY,
    pattern: /\bshell\s*=\s*True\b/,
    unless: LLM_SINK,
  },
  {
    id: "py-os-command",
    scanner: "sast",
    severity: "medium",
    title: "Shell command via {match}()",
    description: "os.system/os.popen always run the command through a shell. If the string is built from variables, it is vulnerable to command injection.",
    remediation: "Use subprocess.run([...], shell=False) with an argument list and validate the inputs.",
    refs: ["CWE-78", "Bandit B605"],
    extensions: PY,
    pattern: /\b(os\.system|os\.popen|commands\.getoutput)\s*\(/,
    unless: LLM_SINK,
  },
  {
    id: "py-sql-injection",
    scanner: "sast",
    severity: "high",
    title: "SQL query built with string formatting",
    description: "The SQL statement is assembled with an f-string, % formatting, .format() or concatenation. Values that reach it from a request (or from an LLM) can change the query and read or modify arbitrary data.",
    remediation: "Use parameterised queries (cursor.execute(\"… WHERE id = %s\", (value,)) or SQLAlchemy bound parameters); never interpolate values into SQL text.",
    refs: ["CWE-89", "Bandit B608", "OWASP A03:2021"],
    extensions: PY,
    pattern: /\.(?:execute|executemany|executescript|exec_driver_sql|raw)\s*\(\s*(?:[fF]["']|[\w.]+\s*(?:\+|%)\s*[\w(])|[fF]"{1,3}\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^"]*\{|[fF]'{1,3}\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^']*\{|["'](?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^"']*["']\s*(?:%\s*[\w(]|\.format\s*\(|\+\s*[\w(])/,
    unless: LLM_SINK,
  },
  {
    id: "py-tls-verify-disabled",
    scanner: "sast",
    severity: "medium",
    title: "TLS certificate verification disabled",
    description: "Certificate verification is turned off, so any party on the network path can impersonate the server and read or alter the traffic, including credentials and documents.",
    remediation: "Remove verify=False. For internal CAs, point verify= (or REQUESTS_CA_BUNDLE) at the Capgemini root CA bundle instead of disabling verification.",
    refs: ["CWE-295", "Bandit B501"],
    extensions: PY,
    pattern: /\bverify\s*=\s*False\b|\bssl\._create_unverified_context\b|\bcert_reqs\s*=\s*["']?(?:ssl\.)?CERT_NONE/,
  },
  {
    id: "py-debug-enabled",
    scanner: "sast",
    severity: "medium",
    title: "Debug mode enabled",
    description: "Running Flask/Werkzeug or Django in debug mode exposes stack traces, configuration and — for Werkzeug — an interactive debugger that allows code execution.",
    remediation: "Drive debug mode from configuration (default off) and make sure production deployments run with debug disabled behind a production WSGI/ASGI server.",
    refs: ["CWE-489", "Bandit B201"],
    extensions: PY,
    pattern: /\.run\s*\([^)\n]*\bdebug\s*=\s*True|^\s*DEBUG\s*=\s*True\b/,
  },
  {
    id: "py-weak-hash",
    scanner: "sast",
    severity: "low",
    title: "Weak hash algorithm ({match})",
    description: "MD5 and SHA-1 are broken for collision resistance and must not be used for signatures, integrity checks or password storage.",
    remediation: "Use hashlib.sha256 (or blake2b). For non-security uses such as cache keys, pass usedforsecurity=False to document the intent.",
    refs: ["CWE-327", "Bandit B324"],
    extensions: PY,
    pattern: /\bhashlib\.(md5|sha1)\s*\(|\bhashlib\.new\s*\(\s*["'](md5|sha1)["']/i,
    unless: /usedforsecurity\s*=\s*False/,
  },
  {
    id: "py-insecure-tempfile",
    scanner: "sast",
    severity: "low",
    title: "Insecure temporary file (tempfile.mktemp)",
    description: "tempfile.mktemp() returns a name without creating the file, leaving a race window in which another process can create or replace it.",
    remediation: "Use tempfile.NamedTemporaryFile() or tempfile.mkstemp().",
    refs: ["CWE-377", "Bandit B306"],
    extensions: PY,
    pattern: /\btempfile\.mktemp\s*\(/,
  },
  {
    id: "py-bind-all-interfaces",
    scanner: "sast",
    severity: "low",
    title: "Service binds to all network interfaces",
    description: "Binding to 0.0.0.0 exposes the service on every interface of the host. This is expected inside a container, but on a VM or developer machine it makes the API reachable from the whole network.",
    remediation: "Bind to 127.0.0.1 unless the service runs in a container behind an ingress, and restrict exposure with network rules or a private endpoint.",
    refs: ["CWE-1327", "Bandit B104"],
    extensions: PY,
    pattern: /["']0\.0\.0\.0["']/,
  },
  // JavaScript / TypeScript
  {
    id: "js-eval",
    scanner: "sast",
    severity: "high",
    title: "Dynamic code execution ({match})",
    description: "eval() and new Function() compile and run arbitrary JavaScript. Any attacker-influenced input (request data, stored content, model output) leads to code execution — on the server this is RCE, in the browser XSS.",
    remediation: "Remove eval/new Function. Use JSON.parse for data and explicit lookup tables for dynamic behaviour.",
    refs: ["CWE-95", "Semgrep javascript.lang.security.audit.code-string-concat"],
    extensions: JS,
    pattern: /(?:^|[^\w.$])(eval)\s*\(|\b(new\s+Function)\s*\(/,
    unless: LLM_SINK,
  },
  {
    id: "js-command-injection",
    scanner: "sast",
    severity: "high",
    title: "Shell command built from variables ({match})",
    description: "child_process.exec/execSync run the string through a shell. Interpolating or concatenating variables into it allows command injection.",
    remediation: "Use execFile/spawn with an argument array (shell: false) and validate any variable parts.",
    refs: ["CWE-78", "Semgrep javascript.lang.security.detect-child-process"],
    extensions: JS,
    pattern: /(?:^|[^\w.$]|child_process\.|cp\.)(exec|execSync)\s*\(\s*(?:\x60[^\x60]*\$\{|["'][^"']*["']\s*\+|\w+\s*\+)/,
    unless: LLM_SINK,
  },
  {
    id: "js-dangerously-set-inner-html",
    scanner: "sast",
    severity: "medium",
    title: "React dangerouslySetInnerHTML",
    description: "Rendering raw HTML bypasses React's escaping. If the content comes from users, documents or an LLM (which can be prompt-injected into emitting <script> or event handlers), this is cross-site scripting.",
    remediation: "Render text instead of HTML, or sanitise with DOMPurify before rendering. For LLM output, render Markdown with a sanitising renderer.",
    refs: ["CWE-79", "OWASP LLM05:2025"],
    extensions: JS,
    pattern: /dangerouslySetInnerHTML/,
  },
  {
    id: "js-inner-html",
    scanner: "sast",
    severity: "medium",
    title: "Assignment to {match}",
    description: "Assigning to innerHTML/outerHTML parses the string as HTML; untrusted content leads to cross-site scripting.",
    remediation: "Use textContent, or sanitise the HTML with DOMPurify first.",
    refs: ["CWE-79"],
    extensions: JS,
    pattern: /\.(innerHTML|outerHTML)\s*\+?=(?!=)|\b(document\.write)\s*\(/,
    unless: /\.(?:inner|outer)HTML\s*=\s*(?:""|''|``)\s*;?\s*$/,
  },
  {
    id: "js-sql-injection",
    scanner: "sast",
    severity: "high",
    title: "SQL query built with template literal or concatenation",
    description: "The query string interpolates variables directly into SQL. Values from requests or model output can alter the query.",
    remediation: "Use parameterised queries (placeholders with a values array) or a query builder / ORM with bound parameters. Tagged templates such as sql`…` from a safe library are fine.",
    refs: ["CWE-89", "OWASP A03:2021"],
    extensions: JS,
    pattern: /\.(?:query|execute|raw|unsafe|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(\s*\x60[^\x60]*\$\{|\.(?:query|execute|raw)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*\+/i,
  },
  {
    id: "js-tls-verify-disabled",
    scanner: "sast",
    severity: "medium",
    title: "TLS certificate verification disabled",
    description: "rejectUnauthorized: false or NODE_TLS_REJECT_UNAUTHORIZED=0 turns off certificate validation, enabling man-in-the-middle attacks on outbound calls (including calls to model endpoints).",
    remediation: "Remove the override and trust the internal CA via NODE_EXTRA_CA_CERTS instead.",
    refs: ["CWE-295"],
    extensions: JS,
    pattern: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED["']?\]?\s*=\s*["']?0/,
  },
  {
    id: "cors-wildcard",
    scanner: "sast",
    severity: "low",
    title: "CORS allows any origin",
    description: "The API accepts cross-origin requests from any website. Combined with cookie or token based auth this lets third-party pages call the API on behalf of signed-in users.",
    remediation: "Restrict allowed origins to the known front-end domains of the application.",
    refs: ["CWE-942"],
    extensions: CODE,
    pattern: /allow_origins\s*=\s*\[\s*["']\*["']\s*\]|\bCORS\(\s*app\s*\)|CORS_(?:ORIGIN_)?ALLOW_ALL(?:_ORIGINS)?\s*=\s*True|Access-Control-Allow-Origin["']?\s*[,:]\s*["']\*["']|\borigin\s*:\s*["']\*["']|\bcors\(\s*\)/,
  },
];

/* -------------------------------------------------------------------- AI / LLM */

const USER_VALUE = String.raw`(?:\w+\.)?(?:user_?(?:input|query|question|message|prompt|text|request)|query|question|message|msg|input|text_input|request\.\w+|req\.(?:body|query|params)|body\.\w+|payload\.\w+)\b`;
const INTERPOLATED = String.raw`(?:f["']{1,3}[^\n]*?\{\s*${USER_VALUE}|\x60[^\x60\n]*?\$\{\s*${USER_VALUE})`;

const PROMPT_INJECTION = new RegExp(
  String.raw`\b\w*(?:prompt|instruction|system_?(?:msg|message|content))\w*\s*\+?=\s*(?:${INTERPOLATED}|[^\n=;]*?["'\x60]\s*\+\s*${USER_VALUE})` +
    String.raw`|["']?role["']?\s*:\s*["']system["'][^\n]*?["']?content["']?\s*:\s*${INTERPOLATED}`,
  "i",
);

export const AI_RULES: Rule[] = [
  {
    id: "ai-llm-output-execution",
    scanner: "ai",
    severity: "critical",
    title: "LLM output executed as code, shell command or SQL",
    description: "A model response flows directly into eval/exec, a shell or a database query. Anyone who can influence the model — through the prompt, a retrieved document or a web page — can make it emit code that the application then runs with its own privileges.",
    remediation: "Never execute model output directly. Constrain the model to structured output (JSON schema / function calling), validate it against an allow-list, use parameterised queries, and run any generated code only in an isolated sandbox (e.g. Azure Container Apps dynamic sessions) with no secrets or network access.",
    refs: ["OWASP LLM05:2025", "CWE-94", "MITRE ATLAS AML.T0051"],
    extensions: CODE,
    pattern: LLM_SINK,
  },
  {
    id: "ai-trust-remote-code",
    scanner: "ai",
    severity: "high",
    title: "trust_remote_code=True when loading a model",
    description: "trust_remote_code makes Hugging Face transformers download and execute Python files shipped in the model repository. Whoever controls (or compromises) that repository gets code execution in this application.",
    remediation: "Use architectures supported natively by transformers. If remote code is unavoidable, pin a reviewed commit with revision=\"<sha>\", vendor the code into this repository and mirror the model to an internal registry (Azure ML / Azure AI Foundry).",
    refs: ["OWASP LLM03:2025", "CWE-494", "MITRE ATLAS AML.T0010"],
    extensions: CODE,
    pattern: /\btrust_remote_code\s*=\s*True\b|\btrustRemoteCode\s*:\s*true\b/,
  },
  {
    id: "ai-torch-load-unsafe",
    scanner: "ai",
    severity: "high",
    title: "torch.load without weights_only=True",
    description: "torch.load unpickles the checkpoint, so a malicious .pt/.pth/.ckpt file executes arbitrary code when loaded. PyTorch < 2.6 does not restrict this by default.",
    remediation: "Pass weights_only=True (default from PyTorch 2.6), or store weights as safetensors and load them with safetensors.torch.load_file.",
    refs: ["OWASP LLM03:2025", "CWE-502", "MITRE ATLAS AML.T0011"],
    extensions: PY,
    pattern: /\btorch\.load\s*\(/,
    unless: /weights_only\s*=\s*True/,
  },
  {
    id: "ai-dangerous-langchain-flag",
    scanner: "ai",
    severity: "high",
    title: "LangChain safety guard disabled ({match})",
    description: "LangChain gates features that can execute code, make arbitrary HTTP requests or unpickle files behind explicit allow_dangerous_* flags. Enabling the flag removes that protection: a poisoned vector index or a manipulated prompt can lead to code execution or server-side request forgery.",
    remediation: "Remove the flag. Load vector stores only from storage you control (and verify integrity), and give agents narrowly scoped tools instead of generic code or request execution.",
    refs: ["OWASP LLM05:2025", "OWASP LLM06:2025", "CWE-502"],
    extensions: CODE,
    pattern: /\b(allow_dangerous_(?:code|requests|deserialization))\s*=\s*True\b|\b(allowDangerous\w*)\s*:\s*true\b/,
  },
  {
    id: "ai-code-execution-tool",
    scanner: "ai",
    severity: "high",
    title: "Agent can execute arbitrary code or queries ({match})",
    description: "The agent is given a tool or chain that runs Python, shell commands or free-form SQL generated by the model. A prompt injection — via user input or a retrieved document — turns this into code execution or data exfiltration with the application's privileges (excessive agency).",
    remediation: "Replace generic execution tools with narrow, purpose-built functions. If code execution is a requirement, run it in an isolated sandbox without credentials or network access, use a read-only database role with row-level security, and require human approval for side effects.",
    refs: ["OWASP LLM06:2025", "CWE-94", "MITRE ATLAS AML.T0053"],
    extensions: CODE,
    pattern: /\b(PythonREPLTool|PythonAstREPLTool|ShellTool|BashProcess|create_python_agent|create_pandas_dataframe_agent|create_csv_agent|create_spark_dataframe_agent|LLMMathChain|PALChain|SQLDatabaseChain|create_sql_agent)\b|\b(PythonREPL)\s*\(/,
    unless: /^\s*(?:from\s+\S+\s+import|import)\b/,
  },
  {
    id: "ai-prompt-injection",
    scanner: "ai",
    severity: "medium",
    title: "User input concatenated into the prompt",
    description: "User-controlled text is interpolated straight into the prompt or system message. The model cannot distinguish instructions from data, so input such as \"ignore previous instructions…\" can override the system prompt, leak context or trigger tools.",
    remediation: "Keep instructions in the system message and pass user input as a separate user message, clearly delimited. Screen input and retrieved documents with Azure AI Content Safety Prompt Shields, and limit what the model can do with tools.",
    refs: ["OWASP LLM01:2025", "MITRE ATLAS AML.T0051"],
    extensions: CODE,
    pattern: PROMPT_INJECTION,
  },
  {
    id: "ai-secret-in-system-prompt",
    scanner: "ai",
    severity: "medium",
    title: "Credential embedded in a system prompt",
    description: "The system prompt contains what looks like a password, key or token. System prompts are routinely extracted through prompt injection, so anything in them must be considered public.",
    remediation: "Remove credentials from prompts. The application, not the model, should hold secrets (Azure Key Vault / managed identity) and perform authenticated calls on the model's behalf.",
    refs: ["OWASP LLM07:2025", "CWE-798"],
    extensions: CODE,
    pattern: /(?:system_?prompt|system_?message|system_?instructions?|["']?role["']?\s*:\s*["']system["'])[^\n]*?\b(?:password|passwd|api[ _-]?key|secret|access[ _-]?token|bearer token|connection string|credentials?)\b\s*(?:is|=|:)\s*["']?(?=[^\s"']*[\d!@#$%^&*])[^\s"']{6,}/i,
    maskSnippet: true,
  },
  {
    id: "ai-public-llm-endpoint",
    scanner: "ai",
    severity: "medium",
    title: "Public AI provider used instead of tenant-hosted model ({match})",
    description: "Prompts, retrieved documents and user data are sent to a public AI API outside the Capgemini Azure tenant. This bypasses the data-residency, logging and contractual controls that apply to the catalogue and may disclose client or personal data.",
    remediation: "Use a model deployment in the Capgemini Azure tenant (Azure OpenAI / Azure AI Foundry) with Entra ID authentication and a private endpoint. Configure the client with the Azure endpoint (AzureOpenAI / AzureChatOpenAI).",
    refs: ["OWASP LLM02:2025", "GDPR Art. 28", "GDPR Art. 44"],
    extensions: [...CODE, ".yaml", ".yml", ".json", ".toml"],
    pattern: /(https?:\/\/(?:api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.mistral\.ai|api\.cohere\.(?:ai|com)|api\.groq\.com|api\.together\.xyz|api\.deepseek\.com))|(?:^|\W)(?:new\s+)?(OpenAI|AsyncOpenAI|ChatOpenAI|OpenAIEmbeddings|Anthropic|AsyncAnthropic|ChatAnthropic|ChatGoogleGenerativeAI|ChatMistralAI|MistralClient)\s*\(/,
    unless: /azure|base_url\s*=|baseURL\s*:|api_base\s*=|openai_api_base\s*=|endpoint/i,
  },
  {
    id: "ai-unpinned-model-revision",
    scanner: "ai",
    severity: "low",
    title: "Hugging Face model loaded without a pinned revision ({match})",
    description: "from_pretrained() fetches whatever is currently on the default branch. A compromised or silently updated repository changes the model (or its remote code) under you without review.",
    remediation: "Pin revision=\"<commit sha>\" and mirror approved models to an internal registry (Azure ML / Azure AI Foundry model catalogue).",
    refs: ["OWASP LLM03:2025", "MITRE ATLAS AML.T0010"],
    extensions: PY,
    pattern: /\.from_pretrained\s*\(\s*["']([\w.-]+\/[\w.-]+)["']/,
    unless: /\brevision\s*=/,
  },
  {
    id: "ai-gradio-public-share",
    scanner: "ai",
    severity: "high",
    title: "Gradio app published through a public share link",
    description: "launch(share=True) opens a tunnel via gradio.live and makes the app — and everything it can access — reachable from the internet without authentication, bypassing corporate network controls.",
    remediation: "Remove share=True. Host the UI on Azure (App Service / Container Apps) behind Entra ID authentication.",
    refs: ["CWE-668", "OWASP LLM02:2025"],
    extensions: PY,
    pattern: /\.launch\s*\([^)\n]*\bshare\s*=\s*True/,
  },
  {
    id: "ai-prompt-logging",
    scanner: "ai",
    severity: "low",
    title: "Full prompt or conversation written to logs",
    description: "Prompts and messages often contain personal data, client information or retrieved confidential documents. Logging them copies that data into log stores with broader access and longer retention.",
    remediation: "Log metadata (token counts, latency, request id) instead of content, or redact with Presidio before logging. If content logging is required for evaluation, store it in a dedicated, access-controlled store with retention limits.",
    refs: ["OWASP LLM02:2025", "CWE-532"],
    extensions: CODE,
    pattern: /\b(?:logger|logging|log|console|print)\b[\w.]*\s*\([^\n]*(?:[(,+]\s*|\{\s*|\$\{\s*)(?:prompt|full_prompt|messages|user_input|chat_history|system_prompt)\b/,
  },
];

/* --------------------------------------------------------- bestand/repo-niveau */

/** LLM-aanroepen waarvoor een output-token limiet verwacht wordt. */
export const LLM_CALL = /\b(?:chat\.completions\.create|completions\.create|ChatCompletion\.create|Completion\.create|messages\.create|responses\.create|generate_content|getChatCompletions|generateText|streamText)\s*\(|(?:^|\W)(?:new\s+)?(?:AzureChatOpenAI|ChatOpenAI|ChatAnthropic)\s*\(|\bllm\.(?:invoke|ainvoke|predict|stream)\s*\(/;

export const TOKEN_LIMIT = /max_tokens|max_completion_tokens|max_output_tokens|max_new_tokens|maxTokens|maxOutputTokens|maxCompletionTokens|max_length\s*=|num_predict/;

/** Imports van LLM-SDK's (Python en JS/TS). */
export const LLM_SDK_IMPORT = /^\s*(?:from|import)\s+(openai|anthropic|langchain[\w.]*|llama_index[\w.]*|semantic_kernel[\w.]*|azure\.ai\.inference|azure\.ai\.openai|google\.generativeai|mistralai|cohere)\b|from\s+["'](openai|@anthropic-ai\/sdk|@azure\/openai|ai|@ai-sdk\/[\w-]+|langchain|@langchain\/[\w-]+|@azure-rest\/ai-inference)["']|require\(\s*["'](openai|@anthropic-ai\/sdk|@azure\/openai|ai|langchain|@langchain\/[\w-]+)["']\s*\)/gm;

/** Verwijzingen naar guardrails / content safety. */
export const GUARDRAIL = /azure[._-]ai[._-]contentsafety|@azure-rest\/ai-content-safety|ContentSafetyClient|prompt[_ -]?shields?|shieldPrompt|nemoguardrails|guardrails|llm[_-]guard|presidio|moderations?\.create|\.moderations\b|lakera|rebuff/i;
