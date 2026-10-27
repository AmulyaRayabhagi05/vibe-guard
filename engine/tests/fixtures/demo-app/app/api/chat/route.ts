import openai from "@/lib/ai";

export async function POST(req: Request) {
  const body = await req.json();
  const r = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: `You are support for ${body.company}. Be concise.` },
      { role: "user", content: body.question },
    ],
  });
  return Response.json({ answer: r.choices[0].message.content });
}
