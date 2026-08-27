const documentation = "'use server' export async function erase() { await db.user.delete() }"
// 'use server'
// export async function erase() { await db.user.delete() }

export async function listAccounts() {
  return db.account.findMany()
}

export async function inlineAction(accountId: string) {
  'use server'
  await db.account.delete({ where: { id: accountId } })
}
