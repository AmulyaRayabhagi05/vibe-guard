# VibeCheck (vibe-guard)

An automated AST-driven security analysis and DPO-fine-tuned remediation engine for AI-generated codebases, built as a VS Code extension.

A free VS Code extension that finds and fixes security holes and WCAG accessibility issues in AI-generated ("vibe-coded") apps, and traces the AI inside them. Everything runs on your machine.

- **Scan:** 66 rules covering 35 app-security, 16 AI (OWASP Top 10 for LLM apps) and 15 WCAG 2.2 accessibility issues. Rules run on Opengrep, secrets are found with TruffleHog, and code context comes from Tree-sitter.
- **Fix:** a local model served by Ollama (DeepSeek-Coder, later the DPO-tuned `vibecheck-coder`) writes the patch. Before you see a patch, it is checked to parse, to remove the finding, and to add no new findings. Hardcoded secrets get a rule-based fix that needs no model.
- **Scan a link:** paste a GitHub repo or a website.
  - **Repos** are shallow-cloned to a temp folder and never run. The scan covers code, full git history and dependencies (OSV-Scanner, if installed).
  - **Websites** get passive checks: their own JS bundles, public source maps and response headers, plus a live WCAG check with axe-core.
- **AI observability:** a local MLflow server (127.0.0.1 only) records traces, latency, errors, tokens, model, provider and cost, with cost broken down and charted over time. "Trace my app" instruments your app's AI calls. A guard flags prompt-injection attempts, leaked secrets or personal data, and calls over budget.
- **Audit:** an append-only, hash-chained log records every scan, patch and decision. You can export it as HTML, JSON or CSV.

## Cost: $0

| Piece | License |
|---|---|
| Opengrep | LGPL-2.1 |
| TruffleHog | AGPL-3.0, run as an unmodified binary |
| Tree-sitter | MIT |
| SQLite | public domain |
| Ollama | MIT |
| MLflow | Apache-2.0 |
| axe-core | MPL-2.0 |
| Playwright | Apache-2.0 |
| truststore | MIT |

Training runs on Kaggle's free GPUs; see [docs/training.md](docs/training.md).

## Run it (development)

```bash
# 1. Engine
cd engine
uv venv .venv && uv pip install -e ".[dev,observability,a11y]"
.venv/Scripts/python -m vibecheck_engine setup                # downloads pinned Opengrep + TruffleHog, checks hashes
.venv/Scripts/python -m playwright install chromium            # only for live WCAG checks
.venv/Scripts/python -m pytest -q                              # 15 tests

# 2. Fix model (optional; secrets are fixed without it)
ollama pull deepseek-coder:6.7b-instruct

# 3. Extension
cd ../extension && npm install && npm run compile
# Open the repo in VS Code and press F5 ("Run VibeCheck extension")
```

The engine looks for its Python in `engine/.venv`. Point `vibecheck.pythonPath` / `vibecheck.enginePath` elsewhere if needed.

## CLI

```bash
python -m vibecheck_engine scan path/to/app            # human-readable
python -m vibecheck_engine scan . --json --fail-on high   # CI gate
python -m vibecheck_engine scan-link owner/repo
python -m vibecheck_engine scan-link https://yoursite.com
python -m vibecheck_engine a11y http://localhost:3000   # WCAG 2.2 A/AA via axe-core
python -m vibecheck_engine mlflow start                 # local tracing server
python -m vibecheck_engine traces --hours 24
python -m vibecheck_engine verify-audit . && python -m vibecheck_engine report . --format html
```

## Layout

```
engine/      Python engine (scanners, fixer, link scanning, a11y, MLflow layer, audit, JSON-RPC)
rules/       Opengrep rules + test fixtures (app/, ai/, a11y/); run `opengrep test --config X.yaml X.tsx`
extension/   VS Code extension (TypeScript): diagnostics, CodeLens, diff review, Vault/Traces/Cost/Audit views
dataset/     Builds the 20k-app DPO dataset with local models
training/    DPO + QLoRA training (Unsloth/TRL), GGUF export, Ollama Modelfile, evaluation
```

## Privacy

- **Code and scanning:** your code never leaves the machine. TruffleHog runs with `--no-verification`, so found keys are never sent to the provider to test them.
- **Network:** the extension talks to the engine over stdio, with no open port. MLflow binds to 127.0.0.1.
- **Website scans:** these only download what a normal visit would. Deeper checks stay locked until you prove you own the site with a DNS TXT record or `/.well-known/vibecheck.txt`.
