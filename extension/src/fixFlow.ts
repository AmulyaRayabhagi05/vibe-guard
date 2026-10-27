// Propose a patch, show it as a diff, and accept or reject it. Only validated patches are offered.
import * as vscode from "vscode";
import { Engine } from "./engine";

const SCHEME = "vibecheck-patch";
const contents = new Map<string, string>();

export function registerPatchDocuments(): vscode.Disposable {
  return vscode.workspace.registerTextDocumentContentProvider(SCHEME, {
    provideTextDocumentContent: (uri) => contents.get(uri.path) ?? "",
  });
}

interface Patch {
  patch_id: number;
  finding: { title: string; path: string };
  model: string;
  original: string;
  patched: string;
  checks: { name: string; ok: boolean; detail: string }[];
  ok: boolean;
  latency_ms: number;
  input_tokens: number;
  output_tokens: number;
}

export async function runFix(engine: Engine, workspace: string, findingId: string, onDone: () => void): Promise<void> {
  const testCommand = vscode.workspace.getConfiguration("vibecheck").get<string>("testCommand") || undefined;
  const patch = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: "VibeCheck is writing and checking a fix…" },
    () => engine.request<Patch>("fix.propose", { workspace, finding_id: findingId, test_command: testCommand }),
  );
  const checks = patch.checks.map((c) => `${c.ok ? "✓" : "✗"} ${c.name}`).join("  ");
  const base = `/${patch.patch_id}/${patch.finding.path}`;
  contents.set(`${base}.before`, patch.original);
  contents.set(`${base}.after`, patch.patched);
  await vscode.commands.executeCommand(
    "vscode.diff",
    vscode.Uri.from({ scheme: SCHEME, path: `${base}.before` }),
    vscode.Uri.from({ scheme: SCHEME, path: `${base}.after` }),
    `VibeCheck fix · ${patch.finding.path}`,
    { preview: true },
  );
  const meta = patch.model.startsWith("quickfix")
    ? "rule-based fix"
    : `${patch.model} · ${(patch.latency_ms / 1000).toFixed(1)}s · ${patch.input_tokens + patch.output_tokens} tokens`;
  if (!patch.ok) {
    const choice = await vscode.window.showWarningMessage(
      `The fix didn't pass every check, so it isn't offered for one-click apply. ${checks}`,
      { modal: false },
      "Reject",
      "Apply anyway",
    );
    if (choice !== "Apply anyway") {
      await engine.request("fix.decide", { workspace, patch_id: patch.patch_id, accept: false });
      return;
    }
  } else {
    const choice = await vscode.window.showInformationMessage(
      `${patch.finding.title}: ${checks} (${meta})`,
      "Accept patch",
      "Reject",
    );
    if (choice !== "Accept patch") {
      await engine.request("fix.decide", { workspace, patch_id: patch.patch_id, accept: false });
      vscode.window.setStatusBarMessage("VibeCheck: patch rejected (logged)", 4000);
      return;
    }
  }
  await engine.request("fix.decide", { workspace, patch_id: patch.patch_id, accept: true });
  await vscode.commands.executeCommand("workbench.action.closeActiveEditor");
  vscode.window.setStatusBarMessage("VibeCheck: patch applied and logged to the audit trail", 5000);
  onDone();
}
