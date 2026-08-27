'use server'

import { db } from '@/lib/db'

export async function removeProject(projectId: string) {
  await db.project.delete({ where: { id: projectId } })
}
