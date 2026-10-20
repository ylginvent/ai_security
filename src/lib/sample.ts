import JSZip from "jszip";

/**
 * Demo-asset "Contoso RAG Assistant": een bewust kwetsbare FastAPI + LangChain RAG-bot met
 * React-frontend, die in alle scanners bevindingen oplevert.
 * Alle "secrets" zijn nep en worden pas runtime samengesteld, zodat er geen volledig
 * token-patroon letterlijk in deze repository staat (GitHub push protection).
 */

export const SAMPLE_FILE_NAME = "contoso-rag-assistant.zip";

const ROOT = "contoso-rag-assistant";

const lines = (...l: string[]) => `${l.join("\n")}\n`;

function fakeSecrets() {
  return {
    openaiKey: ["sk", "proj", ["AiAssetGateDemo", "0000000000", "NotARealKey", "abcdefghij"].join("")].join("-"),
    awsKeyId: ["AK", "IA", "DEMO", "FAKE", "KEY", "23456"].join(""),
    awsSecret: ["DemoSecret", "NotReal", "x".repeat(23)].join(""),
    storageConn: [
      "DefaultEndpointsProtocol=https",
      "AccountName=contosoraghrdocs",
      ["Account", "Key=", "Q29udG9zb0RlbW8", "x".repeat(64), "Tm90UmVhbA", "=="].join(""),
      "EndpointSuffix=core.windows.net",
    ].join(";"),
    aoaiKey: ["dec0de", "0".repeat(20), "facade"].join(""),
    dbPassword: ["Rag", "Demo", "2026!"].join("-"),
    sessionSecret: ["c9f2", "Kx81", "Lq0Z", "7mWd"].join(""),
  };
}

const enc = new TextEncoder();

/** Protocol-0 pickle die bij het laden `posix.system("echo compromised")` aanroept (onschadelijk commando). */
function maliciousPickle(): Uint8Array {
  return enc.encode("(dp0\nS'model'\np1\ncposix\nsystem\np2\n(S'echo compromised'\np3\ntp4\nRp5\ns.");
}

/** Schone protocol-2 pickle: {"labels": ["hr", "finance", "it"]}. */
function labelMapPickle(): Uint8Array {
  const X = (s: string) => {
    const b = enc.encode(s);
    return [0x58, b.length & 0xff, (b.length >> 8) & 0xff, 0, 0, ...Array.from(b)];
  };
  return new Uint8Array([
    0x80, 0x02, 0x7d, 0x71, 0x00, 0x28,
    ...X("labels"), 0x71, 0x01, 0x5d, 0x71, 0x02, 0x28,
    ...X("hr"), 0x71, 0x03, ...X("finance"), 0x71, 0x04, ...X("it"), 0x71, 0x05,
    0x65, 0x75, 0x2e,
  ]);
}

/** Minimale geldige safetensors-file (2x2 float32 nullen). */
function safetensors(): Uint8Array {
  let header = JSON.stringify({ __metadata__: { format: "pt" }, "embeddings.weight": { dtype: "F32", shape: [2, 2], data_offsets: [0, 16] } });
  while (header.length % 8) header += " ";
  const h = enc.encode(header);
  const out = new Uint8Array(8 + h.length + 16);
  new DataView(out.buffer).setUint32(0, h.length, true);
  out.set(h, 8);
  return out;
}

function files(): Record<string, string | Uint8Array> {
  const s = fakeSecrets();
  return {
    "README.md": lines(
      "# Contoso RAG Assistant",
      "",
      "HR policy assistant for Contoso employees. It answers questions about leave, expenses and payroll using",
      "retrieval-augmented generation over the HR policy library, and lets HR analysts run ad-hoc headcount",
      "reports in natural language.",
      "",
      "> **Demo asset for AI Asset Gate.** This project deliberately contains security issues so the gate has",
      "> something to find. All credentials in it are fake.",
      "",
      "## Architecture",
      "",
      "| Component | Location | Notes |",
      "|---|---|---|",
      "| API | `app/main.py` | FastAPI, `/ask` and `/report` endpoints |",
      "| Retrieval | `app/rag.py` | LangChain + FAISS index of the HR policy PDFs |",
      "| Analytics agent | `app/agent.py` | LLM-generated Python over the headcount export |",
      "| Reranker | `app/models.py` | Cross-encoder from the Hugging Face Hub |",
      "| Intent classifier | `models/classifier.pkl` | scikit-learn, trained by the data team |",
      "| Chat widget | `frontend/` | React + TypeScript |",
      "| Infrastructure | `infra/main.bicep` | Storage account and Azure OpenAI |",
      "",
      "## Running locally",
      "",
      "```bash",
      "pip install -r requirements.txt",
      "uvicorn app.main:app --reload",
      "```",
      "",
      "The pilot UI can be started with `python -m app.ui`.",
    ),
    "requirements.txt": lines(
      "fastapi==0.95.2",
      "uvicorn==0.22.0",
      "langchain==0.0.171",
      "openai==1.3.5",
      "faiss-cpu==1.7.4",
      "torch==1.13.1",
      "transformers==4.30.0",
      "PyYAML==5.3.1",
      "requests==2.25.1",
      "Jinja2==2.11.2",
      "joblib==1.2.0",
      "pandas==2.0.3",
      "gradio>=3.30",
      "python-dotenv",
    ),
    ".env": lines(
      "# Local development settings",
      "AZURE_OPENAI_ENDPOINT=https://contoso-rag.openai.azure.com/",
      `AZURE_OPENAI_API_KEY=${s.aoaiKey}`,
      `AWS_SECRET_ACCESS_KEY=${s.awsSecret}`,
      `DATABASE_URL=postgresql://rag_admin:${s.dbPassword}@contoso-rag-db.postgres.database.azure.com:5432/rag`,
      "LOG_LEVEL=debug",
    ),
    Dockerfile: lines(
      "FROM python:latest",
      "",
      "WORKDIR /app",
      "",
      "# Node is needed to build the chat widget; poppler for PDF ingestion",
      "RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install -y nodejs poppler-utils",
      "",
      "COPY requirements.txt .",
      "RUN pip install -r requirements.txt",
      "",
      "COPY . .",
      "RUN cd frontend && npm ci && npm run build",
      "",
      "ENV ADMIN_PASSWORD=contoso-admin-2024",
      "EXPOSE 8000",
      'CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]',
    ),
    "app/__init__.py": "",
    "app/config.py": String.raw`"""Runtime configuration for the Contoso RAG Assistant."""
import yaml

# TODO(pilot): move these to Key Vault before go-live
OPENAI_API_KEY = "${s.openaiKey}"
AZURE_STORAGE_CONNECTION_STRING = "${s.storageConn}"
AWS_ACCESS_KEY_ID = "${s.awsKeyId}"
AWS_REGION = "eu-west-1"
SESSION_SECRET = "${s.sessionSecret}"

POLICY_CONTAINER = "hr-policies"
CHAT_MODEL = "gpt-4o"


def load_settings(path: str = "settings.yaml") -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.load(fh, Loader=yaml.Loader)
`,
    "app/rag.py": String.raw`"""Retrieval-augmented answering over the Contoso HR policy library."""
import logging

from langchain.chat_models import ChatOpenAI
from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores import FAISS

from .config import OPENAI_API_KEY

log = logging.getLogger("contoso.rag")

SYSTEM_PROMPT = "You are the Contoso HR assistant. Answer only from the policy context. For payroll lookups sign in as svc-payroll (password: Payr0ll!2024)."

embeddings = OpenAIEmbeddings(openai_api_key=OPENAI_API_KEY)
vectorstore = FAISS.load_local("vectorstore/hr-policies", embeddings, allow_dangerous_deserialization=True)
llm = ChatOpenAI(model_name="gpt-4o", temperature=0, openai_api_key=OPENAI_API_KEY)


def answer(question: str) -> str:
    docs = vectorstore.similarity_search(question, k=4)
    context = "\n\n".join(doc.page_content for doc in docs)
    prompt = f"{SYSTEM_PROMPT}\n\nContext:\n{context}\n\nQuestion: {question}"
    log.info("Sending prompt to LLM: %s", prompt)
    return llm.predict(prompt)
`,
    "app/agent.py": String.raw`"""Natural-language analytics for HR analysts."""
from langchain.agents import AgentType, initialize_agent
from langchain.tools.python.tool import PythonREPLTool
from openai import OpenAI

from .config import OPENAI_API_KEY
from .rag import llm

client = OpenAI(api_key=OPENAI_API_KEY)

# Free-form analysis over the headcount export (pandas is available in the REPL)
analytics_agent = initialize_agent(
    tools=[PythonREPLTool()],
    llm=llm,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
    verbose=True,
)


def run_report(user_request: str):
    """Ask the model for a Python snippet that computes the requested metric, then run it."""
    completion = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "Write Python that computes the requested HR metric from the dataframe df and stores it in a variable named result. Reply with code only."},
            {"role": "user", "content": user_request},
        ],
    )
    scope = {"df": load_headcount()}
    exec(completion.choices[0].message.content, scope)
    return scope.get("result")


def load_headcount():
    import pandas as pd

    return pd.read_csv("data/headcount.csv")
`,
    "app/db.py": String.raw`"""Employee directory access."""
import sqlite3

DB_PATH = "data/hr.db"


def get_employee(employee_id: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f"SELECT name, grade, salary FROM employees WHERE id = '{employee_id}'")
    return cursor.fetchone()


def run_generated_query(llm_sql: str):
    """Execute SQL written by the analytics agent for ad-hoc reports."""
    conn = sqlite3.connect(DB_PATH)
    return conn.execute(llm_sql).fetchall()
`,
    "app/models.py": String.raw`"""Model loading for reranking and intent classification."""
import joblib
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer


def load_reranker():
    tokenizer = AutoTokenizer.from_pretrained("contoso-ai/hr-policy-reranker", trust_remote_code=True)
    model = AutoModelForSequenceClassification.from_pretrained("contoso-ai/hr-policy-reranker", trust_remote_code=True)
    return tokenizer, model


def load_intent_head(path: str = "models/intent_head.pt"):
    return torch.load(path, map_location="cpu")


def load_classifier(path: str = "models/classifier.pkl"):
    return joblib.load(path)
`,
    "app/tools.py": String.raw`"""Document ingestion helpers."""
import hashlib
import subprocess

import requests


def convert_to_text(upload_path: str) -> str:
    """Convert an uploaded PDF to plain text with the poppler CLI."""
    result = subprocess.run(f"pdftotext {upload_path} -", shell=True, capture_output=True, text=True)
    return result.stdout


def fetch_policy(url: str) -> str:
    # The intranet policy portal uses a self-signed certificate
    return requests.get(url, verify=False, timeout=10).text


def cache_key(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()
`,
    "app/main.py": String.raw`"""HTTP API for the Contoso RAG Assistant."""
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .agent import run_report
from .rag import answer

app = FastAPI(title="Contoso RAG Assistant")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class Question(BaseModel):
    question: str


class ReportRequest(BaseModel):
    request: str


@app.post("/ask")
def ask(q: Question):
    return {"answer": answer(q.question)}


@app.post("/report")
def report(body: ReportRequest):
    return {"result": run_report(body.request)}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
`,
    "app/ui.py": String.raw`"""Gradio UI used during the pilot."""
import gradio as gr

from .rag import answer

demo = gr.Interface(fn=answer, inputs="text", outputs="text", title="Contoso HR Assistant")

if __name__ == "__main__":
    demo.launch(share=True, server_name="0.0.0.0")
`,
    "notebooks/evaluation.ipynb": JSON.stringify(
      {
        cells: [
          { cell_type: "markdown", metadata: {}, source: ["# Retrieval evaluation\n", "Exact-match accuracy on the golden question set."] },
          {
            cell_type: "code",
            execution_count: 1,
            metadata: {},
            outputs: [],
            source: ["import pickle\n", "\n", "with open(\"eval/golden_set.pkl\", \"rb\") as fh:\n", "    golden = pickle.load(fh)"],
          },
          {
            cell_type: "code",
            execution_count: 2,
            metadata: {},
            outputs: [],
            source: ["from app.rag import answer\n", "\n", "scores = [answer(q) == a for q, a in golden]\n", "print(sum(scores) / len(scores))"],
          },
        ],
        metadata: { kernelspec: { display_name: "Python 3", language: "python", name: "python3" } },
        nbformat: 4,
        nbformat_minor: 5,
      },
      null,
      1,
    ),
    "frontend/package.json": JSON.stringify(
      {
        name: "contoso-rag-frontend",
        version: "0.3.0",
        private: true,
        scripts: { build: "vite build", dev: "vite" },
        dependencies: { axios: "^0.21.1", lodash: "^4.17.15", react: "^18.2.0", "react-dom": "^18.2.0" },
      },
      null,
      2,
    ),
    "frontend/package-lock.json": JSON.stringify(
      {
        name: "contoso-rag-frontend",
        version: "0.3.0",
        lockfileVersion: 3,
        requires: true,
        packages: {
          "": {
            name: "contoso-rag-frontend",
            version: "0.3.0",
            dependencies: { axios: "^0.21.1", lodash: "^4.17.15", react: "^18.2.0", "react-dom": "^18.2.0" },
          },
          "node_modules/axios": {
            version: "0.21.1",
            resolved: "https://registry.npmjs.org/axios/-/axios-0.21.1.tgz",
            dependencies: { "follow-redirects": "^1.10.0" },
          },
          "node_modules/follow-redirects": { version: "1.13.3", resolved: "https://registry.npmjs.org/follow-redirects/-/follow-redirects-1.13.3.tgz" },
          "node_modules/js-tokens": { version: "4.0.0", resolved: "https://registry.npmjs.org/js-tokens/-/js-tokens-4.0.0.tgz" },
          "node_modules/lodash": { version: "4.17.15", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz" },
          "node_modules/loose-envify": {
            version: "1.4.0",
            resolved: "https://registry.npmjs.org/loose-envify/-/loose-envify-1.4.0.tgz",
            dependencies: { "js-tokens": "^3.0.0 || ^4.0.0" },
          },
          "node_modules/react": {
            version: "18.2.0",
            resolved: "https://registry.npmjs.org/react/-/react-18.2.0.tgz",
            dependencies: { "loose-envify": "^1.1.0" },
          },
          "node_modules/react-dom": {
            version: "18.2.0",
            resolved: "https://registry.npmjs.org/react-dom/-/react-dom-18.2.0.tgz",
            dependencies: { "loose-envify": "^1.1.0", scheduler: "^0.23.0" },
          },
          "node_modules/scheduler": {
            version: "0.23.0",
            resolved: "https://registry.npmjs.org/scheduler/-/scheduler-0.23.0.tgz",
            dependencies: { "loose-envify": "^1.1.0" },
          },
        },
      },
      null,
      2,
    ),
    "frontend/src/api.ts": lines(
      'import axios from "axios";',
      'import debounce from "lodash/debounce";',
      "",
      "export async function ask(question: string): Promise<string> {",
      '  const { data } = await axios.post("/ask", { question });',
      "  return data.answer;",
      "}",
      "",
      "export const askDebounced = debounce(ask, 300);",
    ),
    "frontend/src/Chat.tsx": lines(
      'import { useState, type FormEvent } from "react";',
      'import { ask } from "./api";',
      "",
      "export function Chat() {",
      '  const [question, setQuestion] = useState("");',
      '  const [answer, setAnswer] = useState("");',
      "",
      "  async function submit(e: FormEvent) {",
      "    e.preventDefault();",
      "    setAnswer(await ask(question));",
      "  }",
      "",
      "  return (",
      '    <form onSubmit={submit} className="chat">',
      '      <input value={question} onChange={(e) => setQuestion(e.target.value)} placeholder="Ask about HR policies" />',
      '      <button type="submit">Ask</button>',
      "      {/* The API returns Markdown already rendered to HTML */}",
      '      <div className="answer" dangerouslySetInnerHTML={{ __html: answer }} />',
      "    </form>",
      "  );",
      "}",
    ),
    "infra/main.bicep": lines(
      "@description('Location for all resources')",
      "param location string = resourceGroup().location",
      "",
      "resource docs 'Microsoft.Storage/storageAccounts@2023-01-01' = {",
      "  name: 'contosoraghrdocs'",
      "  location: location",
      "  sku: {",
      "    name: 'Standard_LRS'",
      "  }",
      "  kind: 'StorageV2'",
      "  properties: {",
      "    allowBlobPublicAccess: true",
      "    minimumTlsVersion: 'TLS1_0'",
      "    supportsHttpsTrafficOnly: false",
      "    publicNetworkAccess: 'Enabled'",
      "  }",
      "}",
      "",
      "resource aoai 'Microsoft.CognitiveServices/accounts@2023-05-01' = {",
      "  name: 'contoso-rag-aoai'",
      "  location: location",
      "  kind: 'OpenAI'",
      "  sku: {",
      "    name: 'S0'",
      "  }",
      "  properties: {",
      "    customSubDomainName: 'contoso-rag-aoai'",
      "    publicNetworkAccess: 'Enabled'",
      "    disableLocalAuth: false",
      "  }",
      "}",
    ),
    ".github/workflows/preview.yml": lines(
      "name: PR preview",
      "on:",
      "  pull_request_target:",
      "    types: [opened, synchronize]",
      "",
      "jobs:",
      "  preview:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "        with:",
      "          ref: ${{ github.event.pull_request.head.sha }}",
      "      - name: Announce preview",
      '        run: echo "Building preview for ${{ github.event.pull_request.title }}"',
      "      - name: Build image",
      "        run: docker build -t contoso-rag:pr-${{ github.event.number }} .",
    ),
    "models/classifier.pkl": maliciousPickle(),
    "models/label_map.pkl": labelMapPickle(),
    "models/embeddings.safetensors": safetensors(),
  };
}

/** Bouwt de demo-zip runtime op (niets hiervan staat als bestand in de repository). */
export async function buildSampleZip(): Promise<Uint8Array> {
  const zip = new JSZip();
  for (const [path, content] of Object.entries(files())) zip.file(`${ROOT}/${path}`, content);
  return zip.generateAsync({ type: "uint8array", compression: "DEFLATE", compressionOptions: { level: 6 } });
}
