// Findings -> editor squiggles + "Fix with VibeCheck" CodeLens.
import * as path from "path";
import * as vscode from "vscode";
import { Finding } from "./engine";

const SEVERITY: Record<Finding["severity"], vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
  info: vscode.DiagnosticSeverity.Hint,
};

export function tagOf(f: Finding): string {
  return f.wcag ? `WCAG ${f.wcag}` : f.cwe || f.owasp || "";
}

export class FindingsIndex {
  readonly collection = vscode.languages.createDiagnosticCollection("vibecheck");
  private byFile = new Map<string, Finding[]>();
  private readonly changed = new vscode.EventEmitter<void>();
  readonly onDidChange = this.changed.event;

  constructor(private root: vscode.Uri) {}

  set(findings: Finding[]): void {
    const showA11y = vscode.workspace.getConfiguration("vibecheck").get<boolean>("showAccessibility", true);
    this.byFile.clear();
    this.collection.clear();
    for (const f of findings) {
      if (!f.start_line || /^https?:/.test(f.path)) continue;
      if (f.category === "a11y" && !showA11y) continue;
      const file = vscode.Uri.file(path.join(this.root.fsPath, f.path)).fsPath;
      const list = this.byFile.get(file) ?? [];
      list.push(f);
      this.byFile.set(file, list);
    }
    for (const [file, list] of this.byFile) {
      this.collection.set(
        vscode.Uri.file(file),
        list.map((f) => {
          const range = new vscode.Range(f.start_line - 1, 0, Math.max(f.end_line, f.start_line) - 1, Number.MAX_SAFE_INTEGER);
          const d = new vscode.Diagnostic(range, `${f.title}: ${f.message}`, SEVERITY[f.severity]);
          d.source = `VibeCheck${tagOf(f) ? " · " + tagOf(f) : ""}`;
          d.code = f.rule_id;
          return d;
        }),
      );
    }
    this.changed.fire();
  }

  forFile(file: string): Finding[] {
    return this.byFile.get(vscode.Uri.file(file).fsPath) ?? [];
  }

  dispose(): void {
    this.collection.dispose();
    this.changed.dispose();
  }
}

export class FixLensProvider implements vscode.CodeLensProvider {
  readonly onDidChangeCodeLenses: vscode.Event<void>;

  constructor(private index: FindingsIndex) {
    this.onDidChangeCodeLenses = index.onDidChange;
  }

  provideCodeLenses(doc: vscode.TextDocument): vscode.CodeLens[] {
    return this.index.forFile(doc.uri.fsPath).flatMap((f) => {
      const range = new vscode.Range(f.start_line - 1, 0, f.start_line - 1, 0);
      const lenses = [];
      if (f.fixable) {
        lenses.push(new vscode.CodeLens(range, { title: `🔒 Fix with VibeCheck (${f.severity})`, command: "vibecheck.fix", arguments: [f.id] }));
      }
      lenses.push(new vscode.CodeLens(range, { title: "Accept risk", command: "vibecheck.ignore", arguments: [f.id] }));
      return lenses;
    });
  }
}

export class FixActionProvider implements vscode.CodeActionProvider {
  constructor(private index: FindingsIndex) {}

  provideCodeActions(doc: vscode.TextDocument, range: vscode.Range): vscode.CodeAction[] {
    return this.index
      .forFile(doc.uri.fsPath)
      .filter((f) => f.fixable && range.start.line + 1 >= f.start_line && range.start.line + 1 <= Math.max(f.end_line, f.start_line))
      .map((f) => {
        const a = new vscode.CodeAction(`Fix with VibeCheck: ${f.title}`, vscode.CodeActionKind.QuickFix);
        a.command = { title: "Fix", command: "vibecheck.fix", arguments: [f.id] };
        return a;
      });
  }
}
