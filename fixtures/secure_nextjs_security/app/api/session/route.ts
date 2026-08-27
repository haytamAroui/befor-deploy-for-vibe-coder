import { cookies } from 'next/headers'

export async function POST() {
  const cookieStore = await cookies()
  const session = 'opaque-session-reference'
  cookieStore.set('session', session, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 3600,
    path: '/',
  })
  return Response.json({ analyticsId: process.env.NEXT_PUBLIC_ANALYTICS_ID })
}
