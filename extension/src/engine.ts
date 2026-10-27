// JSON-RPC client for the Python engine over stdio. One JSON object per line.
import { ChildProcessWithoutNullStreams, spawn } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as readline from "readline";
import * as vscode from "vscode";

export interface Finding {
  id: string;
  rule_id: string;
  title: string;
  message: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: "app" | "secret" | "ai" | "a11y" | "web" | "dependency";
  path: string;
  start_line: number;
  end_line: number;
  cwe: string;
  owasp: string;
  wcag: string;
  source: string;
  snippet: string;
  fixable: boolean;
  extra: Record<string, unknown>;
}

type Pending = { resolve: (v: any) => void; reject: (e: Error) => void };

export class Engine implements vscode.Disposable {
  private proc?: ChildProcessWithoutNullStreams;
  private pending = new Map<number, Pending>();
  private nextId = 1;
  private ready?: Promise<void>;

  constructor(private readonly extensionPath: string, private readonly log: vscode.OutputChannel) {}

  private resolveEngineDir(): string {
    const configured = vscode.workspace.getConfiguration("vibecheck").get<string>("enginePath");
    const candidates = [configured, path.join(this.extensionPath, "engine"), path.join(this.extensionPath, "..", "engine")];
    const found = candidates.find((c) => c && fs.existsSync(path.join(c, "vibecheck_engine")));
    if (!found) {
      throw new Error("VibeCheck engine not found. Set vibecheck.enginePath to the folder with vibecheck_engine.");
    }
    return found;
  }

  private resolvePython(engineDir: string): string {
    const configured = vscode.workspace.getConfiguration("vibecheck").get<string>("pythonPath");
    if (configured) return configured;
    const venv = process.platform === "win32"
      ? path.join(engineDir, ".venv", "Scripts", "python.exe")
      : path.join(engineDir, ".venv", "bin", "python");
    return fs.existsSync(venv) ? venv : process.platform === "win32" ? "python" : "python3";
  }

  private start(): Promise<void> {
    const engineDir = this.resolveEngineDir();
    const python = this.resolvePython(engineDir);
    this.log.appendLine(`Starting engine: ${python} -m vibecheck_engine serve (${engineDir})`);
    const proc = spawn(python, ["-m", "vibecheck_engine", "serve"], {
      cwd: engineDir,
      env: { ...process.env, PYTHONPATH: engineDir, PYTHONIOENCODING: "utf-8", MLFLOW_DISABLE_AGENT_HINT: "1" },
    });
    this.proc = proc;
    proc.stderr.on("data", (d) => this.log.append(d.toString()));
    return new Promise((resolve, reject) => {
      const rl = readline.createInterface({ input: proc.stdout });
      rl.on("line", (line) => {
        let msg: any;
        try {
          msg = JSON.parse(line);
        } catch {
          this.log.appendLine(`engine: ${line}`);
          return;
        }
        if (msg.event === "ready") {
          resolve();
          return;
        }
        const p = this.pending.get(msg.id);
        if (!p) return;
        this.pending.delete(msg.id);
        msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
      });
      proc.on("error", (e) => reject(new Error(`Couldn't start Python (${python}): ${e.message}`)));
      proc.on("exit", (code) => {
        this.log.appendLine(`Engine exited (${code})`);
        for (const p of this.pending.values()) p.reject(new Error("The VibeCheck engine stopped. See the VibeCheck output panel."));
        this.pending.clear();
        this.proc = undefined;
        this.ready = undefined;
        reject(new Error("The engine exited during startup. See the VibeCheck output panel."));
      });
    });
  }

  async request<T = any>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    if (!this.ready) this.ready = this.start();
    await this.ready;
    const id = this.nextId++;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.proc!.stdin.write(JSON.stringify({ id, method, params }) + "\n");
    });
  }

  dispose(): void {
    if (this.proc) {
      this.proc.stdin.write(JSON.stringify({ id: 0, method: "shutdown" }) + "\n");
      setTimeout(() => this.proc?.kill(), 1000);
    }
  }
}
