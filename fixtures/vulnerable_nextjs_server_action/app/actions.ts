'use server'

import { prisma } from '@/lib/db'

export async function deleteAccount(accountId: string) {
  await prisma.account.delete({ where: { id: accountId } })
}
