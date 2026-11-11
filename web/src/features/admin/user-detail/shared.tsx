import { useQuery } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Skeleton } from '@/components/ui/skeleton'
import { apiFetch } from '@/lib/api'

/** Detail queries share the `admin/users` prefix so the user actions refresh them. */
export function useUserData<T>(id: string, part: string) {
  return useQuery({
    queryKey: ['admin', 'users', 'detail', id, part],
    queryFn: () => apiFetch<T>(`/api/admin/users/${id}/${part}`),
  })
}

export function Panel({ title, description, action, children }: { title: string; description?: ReactNode; action?: ReactNode; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-3">
      <div className="flex items-start justify-between gap-4">
        <div className="flex flex-col gap-1">
          <h2 className="text-sm font-semibold">{title}</h2>
          {description ? <p className="text-xs text-muted-foreground">{description}</p> : null}
        </div>
        {action}
      </div>
      {children}
    </section>
  )
}

export function Loading() {
  return (
    <div className="flex flex-col gap-2">
      <Skeleton className="h-10 w-full" />
      <Skeleton className="h-10 w-full" />
      <Skeleton className="h-10 w-full" />
    </div>
  )
}

export function Failed({ what }: { what: string }) {
  return (
    <Alert variant="destructive">
      <AlertDescription>{what}을(를) 불러오지 못했습니다.</AlertDescription>
    </Alert>
  )
}

export const Nothing = ({ children }: { children: ReactNode }) => (
  <p className="rounded-xl border border-dashed p-6 text-center text-sm text-muted-foreground">{children}</p>
)
