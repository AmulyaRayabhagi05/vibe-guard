// Test fixture for rules/ai/js.yaml (ruleid lines must match, ok lines must not).
import OpenAI from "openai";
import { tool } from "ai";
import { exec } from "child_process";

// ruleid: vc-ai-public-env-llm-key
const key = process.env.NEXT_PUBLIC_OPENAI_API_KEY;
// ok: vc-ai-public-env-llm-key
const serverKey = process.env.OPENAI_API_KEY;

// ruleid: vc-ai-browser-client
const browserAi = new OpenAI({ apiKey: key, dangerouslyAllowBrowser: true });
// ok: vc-ai-browser-client
const ai = new OpenAI({ apiKey: serverKey });

export async function POST(req: Request) {
  const body = await req.json();
  // ruleid: vc-ai-user-controlled-model
  const r = await ai.chat.completions.create({
    model: body.model,
    max_tokens: 500,
    messages: [
      // ruleid: vc-ai-prompt-injection-system
      { role: "system", content: `You are a helpful bot for ${body.company}. Rules: be nice.` },
      { role: "user", content: body.question },
    ],
  });
  // ruleid: vc-ai-output-exec
  eval(r.choices[0].message.content);
  // ruleid: vc-ai-output-sql
  await db.query(r.choices[0].message.content);
  return Response.json(r);
}

// ruleid: vc-ai-no-max-tokens
const r2 = await ai.chat.completions.create({ model: "gpt-4o-mini", messages: [] });
// ok: vc-ai-no-max-tokens
const r3 = await ai.chat.completions.create({ model: "gpt-4o-mini", messages: [], max_tokens: 300 });

// ok: vc-ai-prompt-injection-system
const fixed = { role: "system", content: "You are a helpful bot." };

function show(el: HTMLElement, completion: string) {
  // ruleid: vc-ai-output-html
  el.innerHTML = completion;
}

const shell = tool({
  description: "Run a shell command",
  parameters: z.object({ cmd: z.string() }),
  execute: async ({ cmd }) => {
    // ruleid: vc-ai-agent-shell-tool
    return exec(cmd);
  },
});
