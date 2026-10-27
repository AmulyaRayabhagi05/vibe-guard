import { db } from "@/lib/db";

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const user = await db.user.findUnique({ where: { id: params.id } });
  return Response.json(user);
}
