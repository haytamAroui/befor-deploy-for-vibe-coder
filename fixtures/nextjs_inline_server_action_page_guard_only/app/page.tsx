import { db } from "@/lib/db"

export default async function AdminPage() {
  await requireAdmin()

  async function deleteAllRecords() {
    "use server"
    await db.record.deleteMany()
  }

  return <form action={deleteAllRecords}>Delete records</form>
}
