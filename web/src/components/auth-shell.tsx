import { useQuery } from '@tanstack/react-query'
import { useSearch } from '@tanstack/react-router'
import { UserIcon } from 'lucide-react'
import type { ReactNode } from 'react'
import { Separator } from '@/components/ui/separator'
import { appBrandQuery } from '@/lib/app-brand'
import { loginConfigQuery } from '@/lib/fingerprint'

/**
 * The sign-in card. The header (organization, app icon, "<App>에 로그인") is
 * always on screen; only the body folds shut to the header's edge and opens
 * again, so loading and step changes never make the card appear from nothing.
 */
export function AuthShell({
  folded = false,
  identifier,
  badge,
  heading,
  children,
}: {
  folded?: boolean
  identifier?: string
  /** A title for screens that are not a sign-in to one application. */
  heading?: string
  badge?: ReactNode
  children?: ReactNode
}) {
  const { data } = useQuery(loginConfigQuery)
  // The sign-in belongs to the application that asked for it, not always to WorkPass.
  const { oq } = useSearch({ strict: false }) as { oq?: string }
  const brandQuery = useQuery({ ...appBrandQuery(oq ?? ''), enabled: Boolean(oq) })
  const waiting = Boolean(oq) && brandQuery.isPending
  const app = brandQuery.data ?? data?.app
  return (
    <main className="flex min-h-svh items-center justify-center bg-muted p-4 sm:p-6">
      <div className="w-full max-w-md overflow-hidden rounded-2xl bg-background shadow-sm ring-1 ring-foreground/10">
        <div className="flex min-h-44 flex-col items-center justify-center gap-3 px-6 py-7">
          {data && app && !waiting ? (
            <div className="fold-fade flex flex-col items-center gap-3">
              <span className="text-base text-muted-foreground">{data.organization.name}</span>
              {heading ? null : app.icon ? <img src={app.icon} alt="" className="size-12 rounded-xl" /> : null}
              <span className="text-base font-semibold">{heading ?? app.signInTitle}</span>
            </div>
          ) : null}
        </div>
        <div className="fold" data-folded={folded}>
          <div className="fold-inner">
            {badge ? (
              <div className="relative flex justify-center">
                <Separator className="absolute top-1/2" />
                <div className="relative flex size-10 items-center justify-center rounded-full bg-background text-muted-foreground ring-1 ring-foreground/10">
                  {badge}
                </div>
              </div>
            ) : (
              <Separator />
            )}
            <div className="flex flex-col gap-6 px-6 pt-6 pb-8 sm:px-10">
              {identifier ? (
                <div className="flex justify-center">
                  <div className="flex max-w-full items-center gap-2 rounded-full bg-muted px-4 py-2 text-sm">
                    <UserIcon className="size-4 shrink-0 text-muted-foreground" />
                    <span className="truncate">{identifier}</span>
                  </div>
                </div>
              ) : null}
              {children}
            </div>
          </div>
        </div>
      </div>
    </main>
  )
}
