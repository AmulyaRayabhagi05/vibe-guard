// Test fixture for rules/app/js.yaml (ruleid lines must match, ok lines must not).
import express from "express";
import jwt from "jsonwebtoken";
import cors from "cors";
import { exec, execFile } from "child_process";
import fs from "fs";
import DOMPurify from "dompurify";
import { createClient } from "@supabase/supabase-js";

const app = express();

// ruleid: vc-app-public-env-secret
const supa = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!);
// ok: vc-app-public-env-secret
const anon = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);

// ruleid: vc-app-hardcoded-jwt-secret
const t1 = jwt.sign({ id: 1 }, "supersecret123");
// ok: vc-app-hardcoded-jwt-secret
const t2 = jwt.sign({ id: 1 }, process.env.JWT_SECRET!);

// ruleid: vc-app-jwt-decode-no-verify
const claims = jwt.decode(token);

async function find(db, id, name) {
  // ruleid: vc-app-sql-injection-template
  await db.query(`SELECT * FROM users WHERE id = ${id}`);
  // ruleid: vc-app-sql-injection-template
  await db.query("SELECT * FROM users WHERE name = '" + name + "'");
  // ok: vc-app-sql-injection-template
  await db.query("SELECT * FROM users WHERE id = $1", [id]);
}

// ruleid: vc-app-nosql-where
Users.find({ $where: `this.name == '${name}'` });

// ruleid: vc-app-eval
eval(userCode);
// ok: vc-app-eval
eval("1 + 1");

// ruleid: vc-app-command-injection
exec(`convert ${file} out.png`);
// ok: vc-app-command-injection
exec("ls -la");
// ok: vc-app-command-injection
execFile("convert", [file, "out.png"]);
// ok: vc-app-command-injection
const m = /a(b)/.exec(text);

function Bio({ html }) {
  // ruleid: vc-app-dangerous-html
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
function SafeBio({ html }) {
  // ok: vc-app-dangerous-html
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}
// ruleid: vc-app-dangerous-html
el.innerHTML = comment.body;

// ruleid: vc-app-cors-wildcard-credentials
app.use(cors({ origin: "*", credentials: true }));
// ok: vc-app-cors-wildcard-credentials
app.use(cors({ origin: ["https://myapp.com"], credentials: true }));

// ruleid: vc-app-express-idor
app.get("/api/users/:id", async (req, res) => {
  const user = await db.user.findUnique({ where: { id: req.params.id } });
  res.json(user);
});

// ok: vc-app-express-idor
app.get("/api/orders/:orderId", async (req, res) => {
  const order = await db.order.findFirst({ where: { id: req.params.orderId, userId: req.user.id } });
  res.json(order);
});

// ruleid: vc-app-plaintext-password
if (user.password === req.body.password) { login(user); }

// ruleid: vc-app-insecure-cookie
res.cookie("sid", sid, { httpOnly: false });

// ruleid: vc-app-open-redirect
res.redirect(req.query.next);

// ruleid: vc-app-path-traversal
res.sendFile(path.join(__dirname, "uploads", req.query.file));

// ruleid: vc-app-ssrf
const page = await fetch(req.body.url);

// ruleid: vc-app-insecure-random
const resetToken = Math.random().toString(36).slice(2);
// ok: vc-app-insecure-random
const jitter = Math.random() * 100;

// ruleid: vc-app-tls-verify-off
const agent = new https.Agent({ rejectUnauthorized: false });
