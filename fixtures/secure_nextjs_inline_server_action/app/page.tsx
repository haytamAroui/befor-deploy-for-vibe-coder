import { db } from "@/lib/db"

export default async function SettingsPage() {
  async function updateSettings(formData: FormData) {
    "use server"
    await requireUser()
    await db.settings.update({ data: { theme: formData.get("theme") } })
  }

  return <form action={updateSettings}>Save settings</form>
}
