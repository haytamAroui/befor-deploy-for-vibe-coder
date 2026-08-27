'use server'

import { prisma } from '@/lib/db'
import { requireAdmin } from '@/lib/auth'

export async function deleteAccount(accountId: string) {
  await requireAdmin()
  await prisma.account.delete({ where: { id: accountId } })
}
