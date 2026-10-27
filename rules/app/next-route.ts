// Test fixture for rules/app/next-route.yaml
import { auth } from "@/auth";

// ruleid: vc-app-next-route-no-auth
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const user = await db.user.findUnique({ where: { id: params.id } });
  return Response.json(user);
}

// ok: vc-app-next-route-no-auth
export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (!session) return new Response(null, { status: 401 });
  await db.post.delete({ where: { id: params.id, authorId: session.user.id } });
  return new Response(null, { status: 204 });
}
