import { cookies } from 'next/headers'

export async function POST() {
  const cookieStore = await cookies()
  const session = process.env.NEXT_PUBLIC_SESSION_SECRET
  cookieStore.set('session-token', session, {
    httpOnly: false,
    secure: false,
    sameSite: 'none',
  })
  return Response.json({ ok: true })
}
