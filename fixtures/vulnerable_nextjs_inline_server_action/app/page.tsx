import { prisma } from "@/lib/db"

export default async function AccountPage() {
  async function deleteAccount(formData: FormData) {
    "use server"
    await prisma.account.delete({ where: { id: formData.get("accountId") } })
  }

  return <form action={deleteAccount}>Delete account</form>
}
