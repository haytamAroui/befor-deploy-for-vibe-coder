import { db, prisma } from "@/lib/db"

export default async function FormsPage() {
  const arrowAction = async () => {
    "use server"
    await db.item.deleteMany()
  }

  async function directiveAfterCode() {
    const actionName = "update"
    "use server"
    await prisma.item.update({ data: { actionName } })
  }

  return <form action={arrowAction}>Ignored forms</form>
}

export async function exportedAction() {
  "use server"
  await db.item.delete()
}
