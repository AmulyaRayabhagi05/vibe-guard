// Sidebar webview: Vault, Scan link, AI traces, Cost, Audit.
import * as crypto from "crypto";
import * as vscode from "vscode";

export type ViewMessage = { type: string; [k: string]: any };

export class VaultView implements vscode.WebviewViewProvider {
  static readonly id = "vibecheck.vault";
  private view?: vscode.WebviewView;
  private state: Record<string, unknown> = { busy: {} };

  constructor(private readonly extensionUri: vscode.Uri, private readonly onMessage: (m: ViewMessage) => void) {}

  resolveWebviewView(view: vscode.WebviewView): void {
    this.view = view;
    const media = vscode.Uri.joinPath(this.extensionUri, "media");
    view.webview.options = { enableScripts: true, localResourceRoots: [media] };
    const nonce = crypto.randomBytes(16).toString("base64");
    const css = view.webview.asWebviewUri(vscode.Uri.joinPath(media, "vault.css"));
    const js = view.webview.asWebviewUri(vscode.Uri.joinPath(media, "vault.js"));
    view.webview.html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${view.webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="${css}"></head>
<body>
<nav class="tabs" role="tablist" aria-label="VibeCheck views">
  <button role="tab" data-tab="vault">Vault</button><button role="tab" data-tab="link">Scan link</button>
  <button role="tab" data-tab="traces">AI traces</button><button role="tab" data-tab="cost">Cost</button><button role="tab" data-tab="audit">Audit</button>
</nav>
<section data-tab="vault" id="vault"></section>
<section data-tab="link" id="linkview" hidden></section>
<section data-tab="traces" id="traceview" hidden></section>
<section data-tab="cost" id="costview" hidden></section>
<section data-tab="audit" id="auditview" hidden></section>
<script nonce="${nonce}" src="${js}"></script></body></html>`;
    view.webview.onDidReceiveMessage((m: ViewMessage) => (m.type === "ready" ? this.push() : this.onMessage(m)));
  }

  update(patch: Record<string, unknown>): void {
    if (patch.busy) patch.busy = { ...(this.state.busy as object), ...(patch.busy as object) };
    Object.assign(this.state, patch);
    this.push();
  }

  private push(): void {
    this.view?.webview.postMessage({ type: "state", data: this.state });
  }
}
