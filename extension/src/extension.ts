import * as path from "path";
import * as vscode from "vscode";
import { FindingsIndex, FixActionProvider, FixLensProvider } from "./diagnostics";
import { Engine, Finding } from "./engine";
import { registerPatchDocuments, runFix } from "./fixFlow";
import { VaultView, ViewMessage } from "./vaultView";

const MLFLOW_URL = "http://127.0.0.1:5000";
const CODE_FILES = /\.(py|js|jsx|mjs|cjs|ts|tsx|mts|html|htm|vue|svelte|astro|css|scss|sql|rules|json)$/i;

export function activate(context: vscode.ExtensionContext): void {
  const folder = vscode.workspace.workspaceFolders?.[0];
  const log = vscode.window.createOutputChannel("VibeCheck");
  const engine = new Engine(context.extensionPath, log);
  context.subscriptions.push(log, engine, registerPatchDocuments());
  if (!folder) {
    context.subscriptions.push(vscode.commands.registerCommand("vibecheck.scan", () =>
      vscode.window.showInformationMessage("Open a folder to scan it with VibeCheck.")));
    return;
  }
  const workspace = folder.uri.fsPath;
  const index = new FindingsIndex(folder.uri);
  let findings: Finding[] = [];
  let linkFindings: Finding[] = [];
  const config = () => vscode.workspace.getConfiguration("vibecheck");

  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  status.command = "workbench.view.extension.vibecheck";
  status.text = "$(lock) VibeCheck";
  status.show();

  const view = new VaultView(context.extensionUri, (m) => onViewMessage(m));
  context.subscriptions.push(
    index,
    status,
    vscode.window.registerWebviewViewProvider(VaultView.id, view),
    vscode.languages.registerCodeLensProvider({ scheme: "file" }, new FixLensProvider(index)),
    vscode.languages.registerCodeActionsProvider({ scheme: "file" }, new FixActionProvider(index), {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
    }),
  );
  view.update({ showA11y: config().get("showAccessibility"), budget: config().get("monthlyBudget") });

  function show(result: { findings: Finding[]; security_score: number; a11y_score: number; seconds?: number; errors?: string[] }): void {
    findings = result.findings;
    index.set(findings);
    const crit = findings.filter((f) => f.severity === "critical").length;
    status.text = findings.length ? `$(unlock) ${result.security_score} · ${crit} critical` : "$(lock) Secured";
    status.tooltip = `VibeCheck · security ${result.security_score}/100 · accessibility ${result.a11y_score}/100`;
    status.backgroundColor = crit ? new vscode.ThemeColor("statusBarItem.errorBackground") : undefined;
    view.update({ ...result, error: undefined });
  }

  async function guard<T>(what: string, fn: () => Promise<T>): Promise<T | undefined> {
    try {
      return await fn();
    } catch (e: any) {
      const msg = e?.message ?? String(e);
      log.appendLine(`${what} failed: ${msg}`);
      if (/not installed|Set up/i.test(msg)) {
        const pick = await vscode.window.showErrorMessage(`VibeCheck: ${msg}`, "Set up now");
        if (pick) vscode.commands.executeCommand("vibecheck.setup");
      } else {
        vscode.window.showErrorMessage(`VibeCheck: ${msg}`);
      }
      return undefined;
    }
  }

  async function scan(files?: string[]): Promise<void> {
    view.update({ busy: { scan: true } });
    try {
      const res = await guard("Scan", () => engine.request("scan", { workspace, files }));
      if (res) show(res);
    } finally {
      view.update({ busy: { scan: false } });
    }
  }

  async function scanLink(link?: string): Promise<void> {
    link = link?.trim() || (await vscode.window.showInputBox({ prompt: "GitHub repo or website to scan", placeHolder: "https://github.com/owner/repo or https://yoursite.com" }));
    if (!link) return;
    view.update({ busy: { link: true }, linkError: undefined });
    try {
      const res = await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: `VibeCheck: scanning ${link}` },
        () => engine.request("link.scan", { workspace, link }),
      );
      linkFindings = res.findings;
      view.update({ link: res });
    } catch (e: any) {
      view.update({ linkError: e.message });
    } finally {
      view.update({ busy: { link: false } });
    }
  }

  async function checkA11y(url?: string): Promise<void> {
    url = url?.trim() || (await vscode.window.showInputBox({ prompt: "URL to check against WCAG 2.2 (your dev server works)", value: "http://localhost:3000" }));
    if (!url) return;
    view.update({ busy: { link: true }, linkError: undefined });
    try {
      const res = await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: `VibeCheck: checking accessibility of ${url}` },
        () => engine.request("a11y.check", { workspace, url }),
      );
      linkFindings = res.findings;
      view.update({ link: { kind: "website", url, meta: res.meta, notes: [], errors: [], findings: res.findings, a11y_score: res.a11y_score } });
    } catch (e: any) {
      view.update({ linkError: e.message });
    } finally {
      view.update({ busy: { link: false } });
    }
  }

  async function refreshTraces(hours = 24): Promise<void> {
    const res = await guard("Traces", () => engine.request("traces", { hours }));
    if (res) view.update({ traces: res });
  }

  async function refreshAudit(): Promise<void> {
    const res = await guard("Audit", () => engine.request("audit.list", { workspace, limit: 200 }));
    if (res) view.update({ audit: res });
  }

  async function openFinding(id: string): Promise<void> {
    const f = findings.find((x) => x.id === id) ?? linkFindings.find((x) => x.id === id);
    if (!f) return;
    if (/^https?:|^file:/.test(f.path)) {
      vscode.env.openExternal(vscode.Uri.parse(String(f.extra?.help_url || f.path)));
      return;
    }
    const doc = await vscode.workspace.openTextDocument(path.join(workspace, f.path));
    const line = Math.max(0, f.start_line - 1);
    await vscode.window.showTextDocument(doc, { selection: new vscode.Range(line, 0, line, 0) });
  }

  function onViewMessage(m: ViewMessage): void {
    const actions: Record<string, () => unknown> = {
      scan: () => scan(),
      fix: () => vscode.commands.executeCommand("vibecheck.fix", m.id),
      ignore: () => vscode.commands.executeCommand("vibecheck.ignore", m.id),
      open: () => openFinding(m.id),
      scanLink: () => scanLink(m.link),
      a11y: () => checkA11y(m.url),
      traces: () => refreshTraces(m.hours),
      startTracing: () => vscode.commands.executeCommand("vibecheck.startTracing"),
      traceApp: () => vscode.commands.executeCommand("vibecheck.traceApp"),
      openMlflow: () => vscode.commands.executeCommand("vibecheck.openMlflow"),
      audit: () => refreshAudit(),
      verify: () => vscode.commands.executeCommand("vibecheck.verifyAudit"),
      export: () => exportReport(m.format),
      setup: () => vscode.commands.executeCommand("vibecheck.setup"),
    };
    actions[m.type]?.();
  }

  async function exportReport(format = "html"): Promise<void> {
    const res = await guard("Report", () => engine.request("report.export", { workspace, format, days: 30 }));
    if (!res) return;
    const pick = await vscode.window.showInformationMessage(`Audit report saved: ${path.basename(res.path)}`, "Open");
    if (pick) vscode.env.openExternal(vscode.Uri.file(res.path));
    refreshAudit();
  }

  context.subscriptions.push(
    vscode.commands.registerCommand("vibecheck.scan", () => scan()),
    vscode.commands.registerCommand("vibecheck.scanLink", (link?: string) => scanLink(link)),
    vscode.commands.registerCommand("vibecheck.checkA11y", (url?: string) => checkA11y(url)),
    vscode.commands.registerCommand("vibecheck.fix", async (id?: string) => {
      if (!id) {
        const pick = await vscode.window.showQuickPick(
          findings.filter((f) => f.fixable).map((f) => ({ label: f.title, description: `${f.path}:${f.start_line}`, id: f.id })),
          { placeHolder: "Which finding should VibeCheck fix?" },
        );
        id = pick?.id;
      }
      if (id) await guard("Fix", () => runFix(engine, workspace, id!, () => scan()));
    }),
    vscode.commands.registerCommand("vibecheck.ignore", async (id: string) => {
      const reason = await vscode.window.showInputBox({ prompt: "Why is this risk acceptable? (saved in the audit log)" });
      if (reason === undefined) return;
      await guard("Ignore", () => engine.request("finding.ignore", { workspace, finding_id: id, reason }));
      scan();
    }),
    vscode.commands.registerCommand("vibecheck.setup", async () => {
      const res = await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: "VibeCheck: downloading Opengrep and TruffleHog (free, checksum-verified)…" },
        () => guard("Setup", () => engine.request("setup")),
      );
      if (!res) return;
      const models: string[] = res.ollama_models ?? [];
      const hasModel = models.some((m) => m.startsWith("vibecheck-coder") || m.startsWith("deepseek-coder"));
      vscode.window.showInformationMessage(
        `VibeCheck is ready. ${hasModel ? "Fix model found." : "For AI fixes, install Ollama and run: ollama pull deepseek-coder:6.7b-instruct"}`,
      );
      scan();
    }),
    vscode.commands.registerCommand("vibecheck.startTracing", async () => {
      const res = await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: "VibeCheck: starting local MLflow…" },
        () => guard("MLflow", () => engine.request("mlflow.start")),
      );
      if (res?.running) {
        vscode.window.showInformationMessage(`AI tracing is on (${MLFLOW_URL}, local only).`);
        refreshTraces();
      } else if (res?.error) {
        vscode.window.showErrorMessage(`VibeCheck: ${res.error}`);
      }
    }),
    vscode.commands.registerCommand("vibecheck.stopTracing", () => guard("MLflow", () => engine.request("mlflow.stop"))),
    vscode.commands.registerCommand("vibecheck.traceApp", async () => {
      const res = await guard("Trace app", () => engine.request("app.trace", { workspace }));
      if (!res) return;
      vscode.window.showInformationMessage(`Tracing added (${res.files.join(", ")}). ${res.notes.join(" ")}`);
    }),
    vscode.commands.registerCommand("vibecheck.untraceApp", async () => {
      const res = await guard("Untrace app", () => engine.request("app.untrace", { workspace }));
      if (res) vscode.window.showInformationMessage(res.removed.length ? `Removed: ${res.removed.join(", ")}` : "No tracing files found.");
    }),
    vscode.commands.registerCommand("vibecheck.openMlflow", () => vscode.env.openExternal(vscode.Uri.parse(MLFLOW_URL))),
    vscode.commands.registerCommand("vibecheck.verifyAudit", async () => {
      const res = await guard("Audit", () => engine.request("audit.verify", { workspace }));
      if (!res) return;
      res.ok
        ? vscode.window.showInformationMessage(`Audit log verified: ${res.entries} entries, chain intact.`)
        : vscode.window.showErrorMessage(`Audit log chain is broken at entry ${res.broken_at}. History was edited.`);
      refreshAudit();
    }),
    vscode.commands.registerCommand("vibecheck.exportReport", () => exportReport("html")),
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (!config().get("scanOnSave") || !CODE_FILES.test(doc.fileName)) return;
      const rel = path.relative(workspace, doc.fileName);
      if (rel.startsWith("..") || rel.includes(".vibecheck")) return;
      scan([rel.split(path.sep).join("/")]);
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("vibecheck")) {
        view.update({ showA11y: config().get("showAccessibility"), budget: config().get("monthlyBudget") });
        index.set(findings);
      }
    }),
  );

  // Show the last scan's results straight away, then refresh in the background.
  engine.request("findings", { workspace }).then((r) => r && r.findings.length && show(r), () => undefined);
}

export function deactivate(): void {}
