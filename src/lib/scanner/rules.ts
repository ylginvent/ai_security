import type { ScannerId, Severity } from "../types";
import type { SourceFile } from "./archive";

/**
 * Regelgebaseerde code-analyse. SAST-regels zijn afgeleid van Semgrep (p/python, p/javascript)
 * en Bandit; AI-regels volgen de OWASP Top 10 for LLM Applications 2025.
 * `{match}` in titel/omschrijving wordt vervangen door de eerste capture group.
 * Patronen worden per regel toegepast (geen g-flag, geen lookbehind/named groups: target ES2017).
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
  /**
   * `unless` ook toetsen op de volgende N regels, maar alleen als de aanroep op de treffer-regel
   * nog niet gesloten is (meerregelige aanroepen zoals `torch.load(\n path,\n weights_only=True)`).
   */
  unlessLines?: number;
  /** Regel telt alleen als deze regex óók op dezelfde regel matcht. */
  requires?: RegExp;
  /** Extra bestandsfilter naast de extensies. */
  appliesTo?: (f: SourceFile) => boolean;
  /** Waarden na password/secret/key in de snippet maskeren. */
  maskSnippet?: boolean;
}

export const PY = [".py", ".pyi", ".ipynb"];
export const JS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"];
const CODE = [...PY, ...JS];

/** Import-regels: klassenamen daarin zijn nog geen gebruik. */
const IMPORT_LINE = /^\s*(?:from\s+\S+\s+import|import)\b/;

/* ------------------------------------------------------- LLM-output als sink */

/** Variabelen die doorgaans modeloutput bevatten. */
const LLM_VALUE = String.raw`(?:completion|response|resp|reply|answer|generated(?:_\w+)?|llm_\w+|\w+_(?:completion|response|reply)|ai_\w+|model_output|output_text|chain\.(?:run|invoke|predict)|agent\.(?:run|invoke)|llm\.(?:invoke|predict|call))\b`;
const SINK = String.raw`(?:(?:^|[^\w.])(?:eval|exec)|\bos\.(?:system|popen)|\bsubprocess\.\w+|\.(?:execute|executemany|executescript|exec_driver_sql)|\bexecSync|\bchild_process\.exec|\bnew\s+Function)`;

/** Code-uitvoerende of SQL-sink waarvan het eerste argument modeloutput is. */
export const LLM_SINK = new RegExp(
  String.raw`${SINK}\s*\(\s*(?:f["'][^"'\n]*\{\s*|\x60[^\x60]*\$\{\s*)?(?:(?:self|this)\.)?${LLM_VALUE}`,
);

/** Een verwijzing naar modeloutput ergens op de regel (ook als `result.answer` of `marked(response)`). */
export const LLM_OUTPUT_REF = new RegExp(String.raw`(?:^|[^\w])(?:[\w$]+\.){0,4}${LLM_VALUE}`);

/** HTML-sinks: alles wat een string als HTML in de pagina zet. */
const HTML_SINK = /\bdangerouslySetInnerHTML\b|\.(?:innerHTML|outerHTML)\s*\+?=(?!=)|\.insertAdjacentHTML\s*\(|\bdocument\.write(?:ln)?\s*\(|\bunsafe_allow_html\s*=\s*True\b|\bMarkup\s*\(/;

const EMPTY_INNER_HTML = String.raw`\.(?:inner|outer)HTML\s*=\s*(?:""|''|\x60\x60)\s*;?\s*$`;

/* ------------------------------------------------------------------------ SAST */

export const SAST_RULES: Rule[] = [
  // Python
  {
    id: "py-eval-exec",
    scanner: "sast",
    severity: "high",
    title: "Dynamic code execution with {match}()",
    description: "eval()/exec() runs a string as Python code. If any part of that string can be influenced by a user, an uploaded document or a model response, an attacker can run their own code inside the application (remote code execution).",
    remediation: "Remove eval/exec. To read data, use json.loads(text) or ast.literal_eval(text); to choose behaviour dynamically, use a lookup table, e.g. ACTIONS = {\"sum\": do_sum, \"avg\": do_avg}; ACTIONS[name](values).",
    refs: ["CWE-95", "Bandit B307", "Semgrep python.lang.security.audit.eval-detected"],
    extensions: PY,
    pattern: /(?:^|[^\w.])(eval|exec)\s*\(/,
    unless: LLM_SINK,
  },
  {
    id: "py-insecure-deserialization",
    scanner: "sast",
    severity: "medium",
    title: "Insecure deserialisation ({match})",
    description: "pickle-based loading (pickle, dill, joblib, cloudpickle, marshal, pandas.read_pickle, numpy allow_pickle) runs code embedded in the data. Loading a file you created yourself is fine; loading one that a user uploaded or that was downloaded from the internet is equivalent to running the sender's program.",
    remediation: "Only load pickle files you produced yourself and protect them against tampering (store them in a location users cannot write to, or verify an HMAC/signature before loading). For data exchange use JSON or Parquet; for models use safetensors, ONNX or skops (scikit-learn) instead of pickle/joblib.",
    refs: ["CWE-502", "Bandit B301", "OWASP LLM03:2025"],
    extensions: PY,
    pattern: /\b((?:pickle|cPickle|_pickle|dill|joblib|cloudpickle|marshal)\.loads?|pd\.read_pickle|pandas\.read_pickle)\s*\(|\b(np\.load|numpy\.load)\s*\([^)\n]*allow_pickle\s*=\s*True/,
  },
  {
    id: "py-yaml-unsafe-load",
    scanner: "sast",
    severity: "medium",
    title: "Unsafe YAML deserialisation",
    description: "yaml.load() without SafeLoader can create arbitrary Python objects (e.g. !!python/object/apply:os.system), which means code execution when the YAML comes from a user, a repository or a model.",
    remediation: "Replace yaml.load(data) with yaml.safe_load(data), or pass Loader=yaml.SafeLoader explicitly.",
    refs: ["CWE-502", "Bandit B506"],
    extensions: PY,
    pattern: /\byaml\.(?:unsafe_load|load|load_all)\s*\(/,
    unless: /Loader\s*=\s*(?:yaml\.)?(?:SafeLoader|CSafeLoader|BaseLoader)\b/,
    unlessLines: 3,
  },
  {
    id: "py-subprocess-shell",
    scanner: "sast",
    severity: "high",
    title: "Subprocess call with shell=True",
    description: "With shell=True the command line is interpreted by the system shell, so any value inserted into it (file names, user input, model output) can add extra commands, e.g. a file name like \"x; rm -rf /\".",
    remediation: "Pass the command as a list and drop shell=True, e.g. subprocess.run([\"convert\", input_path, output_path], check=True). Validate or allow-list any variable parts.",
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
    description: "os.system/os.popen always run the command through a shell. If the string is built from variables, an attacker who controls one of them can inject extra commands.",
    remediation: "Use subprocess.run([...], check=True) with an argument list (no shell) and validate the inputs, e.g. subprocess.run([\"git\", \"clone\", url], check=True) instead of os.system(\"git clone \" + url).",
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
    description: "The SQL statement is assembled with an f-string, % formatting, .format() or concatenation. A value that reaches it from a request (or from an LLM) can change the query and read or modify arbitrary data.",
    remediation: "Use parameterised queries so values are sent separately from the SQL text, e.g. cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,)) or SQLAlchemy text(\"… WHERE id = :id\") with {\"id\": user_id}. Never put values into the SQL string itself.",
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
    description: "Certificate verification is turned off, so anyone on the network path can impersonate the server and read or alter the traffic, including credentials and documents.",
    remediation: "Remove verify=False. For an internal CA, point verify at the CA bundle instead, e.g. requests.get(url, verify=\"/etc/ssl/certs/capgemini-root.pem\") or set REQUESTS_CA_BUNDLE.",
    refs: ["CWE-295", "Bandit B501"],
    extensions: PY,
    pattern: /\bverify\s*=\s*False\b|\bssl\._create_unverified_context\b|\bcert_reqs\s*=\s*["']?(?:ssl\.)?CERT_NONE/,
    // jwt.decode(..., verify=False) is geen TLS maar een JWT-probleem (eigen regel)
    unless: /\bjwt\.decode\s*\(/,
  },
  {
    id: "jwt-verification-disabled",
    scanner: "sast",
    severity: "high",
    title: "JWT signature verification disabled",
    description: "The token is decoded without checking its signature (or the \"none\" algorithm is accepted). Anyone can then forge a token with any user id or role and the application will trust it.",
    remediation: "Always verify the signature and pin the algorithm, e.g. jwt.decode(token, key, algorithms=[\"RS256\"], audience=\"api://my-app\") (PyJWT) or jwt.verify(token, key, { algorithms: [\"RS256\"] }) (jsonwebtoken). For Entra ID tokens use a library such as MSAL / azure-identity that validates them for you.",
    refs: ["CWE-347", "OWASP A07:2021"],
    extensions: CODE,
    pattern: /["']?verify_signature["']?\s*:\s*False\b|\bjwt\.decode\s*\([^\n]*\bverify\s*=\s*False\b|\balgorithms?\s*[=:]\s*\[?\s*["']none["']/i,
  },
  {
    id: "py-debug-enabled",
    scanner: "sast",
    severity: "medium",
    title: "Debug mode enabled",
    description: "Running Flask/Werkzeug or Django in debug mode exposes stack traces and configuration to users and, for Werkzeug, an interactive debugger that allows anyone who reaches it to run code.",
    remediation: "Read debug mode from configuration with a safe default, e.g. app.run(debug=os.environ.get(\"FLASK_DEBUG\") == \"1\") or DEBUG = os.environ.get(\"DJANGO_DEBUG\") == \"1\", and run production behind gunicorn/uvicorn with debug off.",
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
    remediation: "Use hashlib.sha256(data) (or blake2b). For passwords use a password hash such as argon2 or bcrypt. If the hash is not security-relevant (e.g. a cache key), write hashlib.md5(data, usedforsecurity=False) to document that.",
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
    description: "tempfile.mktemp() returns a file name without creating the file, leaving a window in which another process can create or replace it.",
    remediation: "Use tempfile.NamedTemporaryFile() or tempfile.mkstemp(), which create the file securely in one step.",
    refs: ["CWE-377", "Bandit B306"],
    extensions: PY,
    pattern: /\btempfile\.mktemp\s*\(/,
  },
  {
    id: "py-bind-all-interfaces",
    scanner: "sast",
    severity: "low",
    title: "Service binds to all network interfaces",
    description: "Binding to 0.0.0.0 exposes the service on every network interface of the host. This is expected inside a container, but on a VM or laptop it makes the API reachable from the whole network.",
    remediation: "Bind to 127.0.0.1 unless the service runs in a container behind an ingress, and restrict exposure with network rules or a private endpoint. If it runs in a container, no change is needed — mention it in the submission.",
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
    description: "eval() and new Function() compile and run a string as JavaScript. Any attacker-influenced input (request data, stored content, model output) leads to code execution — on the server this is remote code execution, in the browser cross-site scripting.",
    remediation: "Remove eval/new Function. Use JSON.parse(text) for data and an explicit lookup object for dynamic behaviour, e.g. const handlers = { sum, avg }; handlers[name]?.(values).",
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
    description: "child_process.exec/execSync run the string through a shell. Interpolating or concatenating variables into it lets an attacker who controls one of them inject extra commands.",
    remediation: "Use execFile/spawn with an argument array, e.g. execFile(\"git\", [\"clone\", url]) instead of exec(`git clone ${url}`), and validate any variable parts.",
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
    description: "Rendering raw HTML bypasses React's built-in escaping. If the content comes from users, documents or an LLM (which can be prompt-injected into emitting <script> tags or event handlers), this is cross-site scripting.",
    remediation: "Render the value as text ({value}) instead of HTML. If HTML is really needed, sanitise it first: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}. For Markdown, use a renderer such as react-markdown without rehype-raw.",
    refs: ["CWE-79", "OWASP LLM05:2025"],
    extensions: JS,
    pattern: /dangerouslySetInnerHTML/,
    // modeloutput als HTML: zwaardere AI-regel ai-llm-output-html
    unless: LLM_OUTPUT_REF,
  },
  {
    id: "js-inner-html",
    scanner: "sast",
    severity: "medium",
    title: "Raw HTML inserted with {match}",
    description: "innerHTML, outerHTML, insertAdjacentHTML and document.write parse the string as HTML; untrusted content leads to cross-site scripting.",
    remediation: "Use element.textContent = value for text, or sanitise first: element.innerHTML = DOMPurify.sanitize(html).",
    refs: ["CWE-79"],
    extensions: JS,
    pattern: /\.(innerHTML|outerHTML)\s*\+?=(?!=)|\b(document\.write(?:ln)?)\s*\(|\.(insertAdjacentHTML)\s*\(/,
    unless: new RegExp(`${EMPTY_INNER_HTML}|${LLM_OUTPUT_REF.source}`),
  },
  {
    id: "js-sql-injection",
    scanner: "sast",
    severity: "high",
    title: "SQL query built with template literal or concatenation",
    description: "The query string inserts variables directly into SQL. Values from requests or model output can change the query and read or modify arbitrary data.",
    remediation: "Use placeholders with a separate values array, e.g. db.query(\"SELECT * FROM users WHERE id = $1\", [userId]), or a query builder / ORM with bound parameters. Tagged templates from a safe library (sql`…`, Prisma $queryRaw`…`) are fine.",
    refs: ["CWE-89", "OWASP A03:2021"],
    extensions: JS,
    pattern: /\.(?:query|execute|raw|unsafe|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(\s*\x60[^\x60]*\$\{|\.(?:query|execute|raw)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*\+/i,
  },
  {
    id: "js-tls-verify-disabled",
    scanner: "sast",
    severity: "medium",
    title: "TLS certificate verification disabled",
    description: "rejectUnauthorized: false or NODE_TLS_REJECT_UNAUTHORIZED=0 turns off certificate validation, so anyone on the network path can intercept or alter outbound calls (including calls to model endpoints).",
    remediation: "Remove the override and trust the internal CA instead by setting NODE_EXTRA_CA_CERTS=/path/to/capgemini-root.pem.",
    refs: ["CWE-295"],
    extensions: JS,
    pattern: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED["']?\]?\s*=\s*["']?0/,
  },
  {
    id: "cors-wildcard",
    scanner: "sast",
    severity: "low",
    title: "CORS allows any origin",
    description: "The API accepts cross-origin requests from any website. Combined with cookie or token based authentication, a third-party page can call the API on behalf of a signed-in user.",
    remediation: "List the known front-end domains explicitly, e.g. allow_origins=[\"https://myapp.capgemini.com\"] (FastAPI) or cors({ origin: [\"https://myapp.capgemini.com\"] }) (Express).",
    refs: ["CWE-942"],
    extensions: CODE,
    pattern: /allow_origins\s*=\s*\[\s*["']\*["']\s*\]|\bCORS\(\s*app\s*\)|CORS_(?:ORIGIN_)?ALLOW_ALL(?:_ORIGINS)?\s*=\s*True|Access-Control-Allow-Origin["']?\s*[,:]\s*["']\*["']|\borigin\s*:\s*["']\*["']|\bcors\(\s*\)/,
  },
];

/* -------------------------------------------------------------------- AI / LLM */

const USER_VALUE = String.raw`(?:\w+\.)?(?:user_?(?:input|query|question|message|prompt|text|request)|query|question|message|msg|input|text_input|request\.\w+|req\.(?:body|query|params)|body\.\w+|payload\.\w+)\b`;
const INTERPOLATED = String.raw`(?:f["']{1,3}[^\n]*?\{\s*${USER_VALUE}|\x60[^\x60\n]*?\$\{\s*${USER_VALUE})`;

/**
 * Gebruikersinvoer in een system-/instructieprompt. `user_prompt` / `human_prompt` zijn juist de
 * gebruikersbeurt en tellen niet mee.
 */
const PROMPT_INJECTION = new RegExp(
  String.raw`\b(?!(?:user|human)_?)\w*(?:prompt|instruction|system_?(?:msg|message|content))\w*\s*\+?=\s*(?:${INTERPOLATED}|[^\n=;]*?["'\x60]\s*\+\s*${USER_VALUE})` +
    String.raw`|["']?role["']?\s*:\s*["']system["'][^\n]*?["']?content["']?\s*:\s*${INTERPOLATED}`,
  "i",
);

export const AI_RULES: Rule[] = [
  {
    id: "ai-llm-output-execution",
    scanner: "ai",
    severity: "critical",
    title: "LLM output executed as code, shell command or SQL",
    description: "A model response flows directly into eval/exec, a shell or a database query. Anyone who can influence the model — through the prompt, a retrieved document or a web page — can make it emit code or SQL that the application then runs with its own privileges.",
    remediation: "Never run model output directly. Ask the model for structured output (JSON schema / function calling), validate it against an allow-list (e.g. only known action names and typed parameters), and use parameterised queries. If generated code must run, execute it in an isolated sandbox (e.g. Azure Container Apps dynamic sessions) without secrets or network access.",
    refs: ["OWASP LLM05:2025", "CWE-94", "MITRE ATLAS AML.T0051"],
    extensions: CODE,
    pattern: LLM_SINK,
  },
  {
    id: "ai-llm-output-html",
    scanner: "ai",
    severity: "high",
    title: "LLM output rendered as raw HTML",
    description: "A value that appears to hold a model response (named e.g. response, answer or completion) is inserted into the page as HTML (dangerouslySetInnerHTML, innerHTML, Streamlit unsafe_allow_html, Markup). A prompt injection — for example hidden text in a document the model summarises — can make the model emit a <script> tag, an <img onerror=…> handler or a phishing link that then runs in the user's browser.",
    remediation: "Render model output as text or as Markdown with a sanitising renderer (react-markdown without rehype-raw; Streamlit st.markdown without unsafe_allow_html). If HTML is required, sanitise it first, e.g. DOMPurify.sanitize(answer) in the browser or bleach.clean(answer) in Python.",
    refs: ["OWASP LLM05:2025", "CWE-79"],
    extensions: CODE,
    pattern: HTML_SINK,
    requires: LLM_OUTPUT_REF,
  },
  {
    id: "ai-trust-remote-code",
    scanner: "ai",
    severity: "high",
    title: "trust_remote_code=True when loading a model",
    description: "trust_remote_code makes Hugging Face transformers download and run Python files shipped in the model repository. Whoever controls (or compromises) that repository gets code execution in this application.",
    remediation: "Use a model architecture that transformers supports natively. If remote code is unavoidable, pin a reviewed commit, e.g. from_pretrained(\"org/model\", trust_remote_code=True, revision=\"<commit sha>\"), vendor the code into this repository and mirror the model to an internal registry (Azure ML / Azure AI Foundry).",
    refs: ["OWASP LLM03:2025", "CWE-494", "MITRE ATLAS AML.T0010"],
    extensions: CODE,
    pattern: /\btrust_remote_code\s*=\s*True\b|\btrustRemoteCode\s*:\s*true\b/,
  },
  {
    id: "ai-torch-load-unsafe",
    scanner: "ai",
    severity: "high",
    title: "torch.load without weights_only=True",
    description: "torch.load unpickles the checkpoint, so a malicious .pt/.pth/.ckpt file runs arbitrary code when it is loaded. PyTorch versions before 2.6 do not restrict this by default.",
    remediation: "Write torch.load(path, weights_only=True) (the default from PyTorch 2.6) and upgrade torch to ≥ 2.6, or store weights as safetensors and load them with safetensors.torch.load_file(path).",
    refs: ["OWASP LLM03:2025", "CWE-502", "MITRE ATLAS AML.T0011"],
    extensions: PY,
    pattern: /\btorch\.load\s*\(/,
    unless: /weights_only\s*=\s*True/,
    unlessLines: 4,
  },
  {
    id: "ai-dangerous-langchain-flag",
    scanner: "ai",
    severity: "high",
    title: "LangChain safety guard disabled ({match})",
    description: "LangChain keeps features that can run code, make arbitrary HTTP requests or unpickle files behind explicit allow_dangerous_* flags. Enabling the flag removes that protection: a poisoned vector index or a manipulated prompt can then lead to code execution or requests to internal systems.",
    remediation: "Remove the flag. Load vector stores only from storage you control (and verify their integrity), and give agents narrowly scoped tools instead of generic code or request execution.",
    refs: ["OWASP LLM05:2025", "OWASP LLM06:2025", "CWE-502"],
    extensions: CODE,
    pattern: /\b(allow_dangerous_(?:code|requests|deserialization))\s*=\s*True\b|\b(allowDangerous\w*)\s*:\s*true\b/,
  },
  {
    id: "ai-code-execution-tool",
    scanner: "ai",
    severity: "high",
    title: "Agent can execute arbitrary code or queries ({match})",
    description: "The agent is given a tool or executor that runs Python, shell commands or free-form SQL written by the model, directly on the host. A prompt injection — via user input or a retrieved document — turns this into code execution or data theft with the application's privileges (excessive agency).",
    remediation: "Replace generic execution tools with narrow, purpose-built functions (e.g. a get_sales(region) tool instead of free SQL). If code execution is a requirement, run it in an isolated sandbox without credentials or network access (Docker executor, Azure Container Apps dynamic sessions), use a read-only database role, and require human approval for anything with side effects.",
    refs: ["OWASP LLM06:2025", "CWE-94", "MITRE ATLAS AML.T0053"],
    extensions: CODE,
    pattern: /\b(PythonREPLTool|PythonAstREPLTool|ShellTool|BashProcess|create_python_agent|create_pandas_dataframe_agent|create_csv_agent|create_spark_dataframe_agent|LLMMathChain|PALChain|SQLDatabaseChain|create_sql_agent|LocalCommandLineCodeExecutor)\b|\b(PythonREPL)\s*\(|["'](use_docker)["']\s*:\s*False\b|\b(additional_authorized_imports)\s*=\s*\[\s*["']\*["']/,
    unless: IMPORT_LINE,
  },
  {
    id: "ai-agent-broad-tools",
    scanner: "ai",
    severity: "medium",
    title: "Agent given broad file-system, browser or HTTP tools ({match})",
    description: "The agent can read, write or delete files, drive a browser or send arbitrary HTTP requests, depending on what the model decides. A prompt injection hidden in a user message, document or web page can make it overwrite files, send data to an attacker's server or reach internal services.",
    remediation: "Give the agent only the operations it needs, scoped to a folder or host allow-list, and require human confirmation for write, delete or send actions. Example (LangChain): FileManagementToolkit(root_dir=\"/data/reports\", selected_tools=[\"read_file\", \"list_directory\"]).",
    refs: ["OWASP LLM06:2025", "CWE-250", "CWE-918"],
    extensions: CODE,
    pattern: /\b(FileManagementToolkit|WriteFileTool|DeleteFileTool|MoveFileTool|CopyFileTool|RequestsToolkit|RequestsGetTool|RequestsPostTool|RequestsPutTool|RequestsPatchTool|RequestsDeleteTool|PlayWrightBrowserToolkit|LocalShellTool|ComputerTool)\b/,
    unless: new RegExp(
      `${IMPORT_LINE.source}|selected_tools\\s*=\\s*\\[\\s*["'](?:read_file|list_directory|file_search)["'](?:\\s*,\\s*["'](?:read_file|list_directory|file_search)["'])*\\s*\\]`,
    ),
  },
  {
    id: "ai-prompt-injection",
    scanner: "ai",
    severity: "medium",
    title: "User input concatenated into the system prompt or instructions",
    description: "User-controlled text is inserted straight into the instructions or system message. The model cannot tell instructions from data, so input such as \"ignore previous instructions and …\" can override your rules, leak the system prompt or trigger tools.",
    remediation: "Keep your instructions fixed in the system message and send the user's text as a separate user message, e.g. messages=[{\"role\": \"system\", \"content\": SYSTEM_PROMPT}, {\"role\": \"user\", \"content\": user_input}]. Screen input and retrieved documents with Azure AI Content Safety Prompt Shields, and limit what the model can do with tools.",
    refs: ["OWASP LLM01:2025", "MITRE ATLAS AML.T0051"],
    extensions: CODE,
    pattern: PROMPT_INJECTION,
  },
  {
    id: "ai-secret-in-system-prompt",
    scanner: "ai",
    severity: "medium",
    title: "Credential embedded in a system prompt",
    description: "The system prompt contains what looks like a password, key or token. System prompts are routinely extracted through prompt injection (\"repeat everything above\"), so anything in them must be considered public.",
    remediation: "Remove credentials from prompts and rotate the exposed value. The application, not the model, should hold secrets (Azure Key Vault / managed identity) and make authenticated calls on the model's behalf through a tool.",
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
    remediation: "Use a model deployment in the Capgemini Azure tenant (Azure OpenAI / Azure AI Foundry) with Entra ID authentication and a private endpoint, e.g. AzureOpenAI(azure_endpoint=..., azure_ad_token_provider=...) or AzureChatOpenAI(...) instead of OpenAI()/ChatOpenAI(). If a public provider is approved for this use case, state that in the questionnaire.",
    refs: ["OWASP LLM02:2025", "GDPR Art. 28", "GDPR Art. 44"],
    extensions: [...CODE, ".yaml", ".yml", ".json", ".toml"],
    pattern: /(https?:\/\/(?:api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.mistral\.ai|api\.cohere\.(?:ai|com)|api\.groq\.com|api\.together\.xyz|api\.deepseek\.com|api\.x\.ai|openrouter\.ai\/api|api\.perplexity\.ai|api\.fireworks\.ai|api\.replicate\.com))|(?:^|\W)(?:new\s+)?(OpenAI|AsyncOpenAI|ChatOpenAI|OpenAIEmbeddings|Anthropic|AsyncAnthropic|ChatAnthropic|ChatGoogleGenerativeAI|GenerativeModel|ChatMistralAI|MistralClient|Mistral|Groq|AsyncGroq|ChatGroq|ChatCohere|ChatDeepSeek|ChatXAI)\s*\(|\b(genai\.Client|cohere\.Client(?:V2)?)\s*\(/,
    unless: /azure|base_url\s*=|baseURL\s*:|api_base\s*=|openai_api_base\s*=|endpoint/i,
  },
  {
    id: "ai-unpinned-model-revision",
    scanner: "ai",
    severity: "low",
    title: "Hugging Face model loaded without a pinned revision ({match})",
    description: "from_pretrained() fetches whatever is currently on the model repository's default branch. A compromised or silently updated repository changes the model (or its code) under you without review.",
    remediation: "Pin the exact commit, e.g. AutoModel.from_pretrained(\"org/model\", revision=\"<commit sha>\"), and mirror approved models to an internal registry (Azure ML / Azure AI Foundry model catalogue).",
    refs: ["OWASP LLM03:2025", "MITRE ATLAS AML.T0010"],
    extensions: PY,
    pattern: /\.from_pretrained\s*\(\s*["']([\w.-]+\/[\w.-]+)["']/,
    unless: /\brevision\s*=/,
    unlessLines: 4,
  },
  {
    id: "ai-gradio-public-share",
    scanner: "ai",
    severity: "high",
    title: "Gradio app published through a public share link",
    description: "launch(share=True) opens a tunnel via gradio.live and makes the app — and everything it can access — reachable from the internet without authentication, bypassing corporate network controls.",
    remediation: "Remove share=True (use demo.launch()). Host the UI on Azure (App Service / Container Apps) behind Entra ID authentication.",
    refs: ["CWE-668", "OWASP LLM02:2025"],
    extensions: PY,
    pattern: /\.launch\s*\([^)\n]*\bshare\s*=\s*True/,
  },
  {
    id: "ai-prompt-logging",
    scanner: "ai",
    severity: "low",
    title: "Full prompt or conversation written to logs",
    description: "Prompts and messages often contain personal data, client information or retrieved confidential documents. Logging them (or enabling framework debug/verbose tracing) copies that data into log stores with broader access and longer retention.",
    remediation: "Log metadata (token counts, latency, request id) instead of content, e.g. logger.info(\"llm call\", extra={\"tokens\": usage.total_tokens}), or redact with Presidio before logging. Turn off set_debug/set_verbose in production. If content logging is needed for evaluation, use a dedicated, access-controlled store with a retention limit.",
    refs: ["OWASP LLM02:2025", "CWE-532"],
    extensions: CODE,
    pattern: /\b(?:logger|logging|log|console|print)\b[\w.]*\s*\([^\n]*(?:[(,+]\s*|\{\s*|\$\{\s*)(?:prompt|full_prompt|messages|user_input|chat_history|system_prompt)\b|\b(?:set_debug|set_verbose)\s*\(\s*True\s*\)|\blangchain\.(?:debug|verbose)\s*=\s*True\b/,
  },
];

/* --------------------------------------------------------- bestand/repo-niveau */

/** LLM-aanroepen waarvoor een output-token limiet verwacht wordt. */
export const LLM_CALL = /\b(?:chat\.completions\.create|completions\.create|ChatCompletion\.create|Completion\.create|messages\.create|responses\.create|generate_content|getChatCompletions|generateText|streamText)\s*\(|(?:^|\W)(?:new\s+)?(?:AzureChatOpenAI|ChatOpenAI|ChatAnthropic)\s*\(|\bllm\.(?:invoke|ainvoke|predict|stream)\s*\(/;

/** Bestand verwijst überhaupt naar een LLM (voorkomt dat bijv. Twilio `messages.create` meetelt). */
export const LLM_CONTEXT = /openai|anthropic|claude|\bgpt|\bllm|gemini|genai|mistral|langchain|llama|ollama|bedrock|cohere|groq|\bai["'/]|@ai-sdk/i;

export const TOKEN_LIMIT = /max_tokens|max_completion_tokens|max_output_tokens|max_new_tokens|maxTokens|maxOutputTokens|maxCompletionTokens|max_length\s*=|num_predict/;

/** Imports van LLM-SDK's (Python, JS/TS en C#). */
export const LLM_SDK_IMPORT = /^\s*(?:from|import)\s+(openai|anthropic|langchain[\w.]*|llama_index[\w.]*|semantic_kernel[\w.]*|azure\.ai\.inference|azure\.ai\.openai|google\.generativeai|google\.genai|vertexai|mistralai|cohere|groq|ollama|litellm|crewai|autogen[\w.]*|smolagents|pydantic_ai)\b|^\s*from\s+google\s+import\s+(genai)\b|from\s+["'](openai|@anthropic-ai\/sdk|@azure\/openai|ai|@ai-sdk\/[\w-]+|langchain|@langchain\/[\w-]+|@azure-rest\/ai-inference|@google\/generative-ai|@google\/genai|groq-sdk|@mistralai\/mistralai|ollama)["']|require\(\s*["'](openai|@anthropic-ai\/sdk|@azure\/openai|ai|langchain|@langchain\/[\w-]+|@google\/generative-ai|@google\/genai|groq-sdk|ollama)["']\s*\)|^\s*using\s+(Azure\.AI\.OpenAI|Azure\.AI\.Inference|Microsoft\.SemanticKernel|OpenAI|Anthropic)(?:\.\w+)*\s*;/gm;

/** Verwijzingen naar guardrails / content safety. */
export const GUARDRAIL = /azure[._-]ai[._-]contentsafety|@azure-rest\/ai-content-safety|ContentSafetyClient|prompt[_ -]?shields?|shieldPrompt|nemoguardrails|guardrails|guardrail(?:Identifier|Config|_?id)\b|llm[_-]guard|llama[_-]?guard|prompt[_-]?guard|presidio|moderations?\.create|\.moderations\b|lakera|rebuff/i;
