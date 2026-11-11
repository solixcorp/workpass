import type { ReactNode } from 'react'
import { scopeLabel } from './scopes'

/** A small centred card for pages that ask a person to approve something. */
export function ApprovalCard({ children }: { children: ReactNode }) {
  return (
    <main className="flex min-h-svh items-center justify-center bg-muted p-4 sm:p-6">
      <div className="flex w-full max-w-md flex-col gap-6 rounded-2xl bg-background p-8 shadow-sm ring-1 ring-foreground/10">{children}</div>
    </main>
  )
}

export function ScopeList({ scopes }: { scopes: string[] }) {
  if (scopes.length === 0) return <p className="text-sm text-muted-foreground">내 신원 확인</p>
  return (
    <ul className="flex flex-col gap-3">
      {scopes.map((scope) => {
        const label = scopeLabel(scope)
        return (
          <li key={scope} className="flex flex-col gap-0.5">
            <span className="text-sm font-medium">{label.title}</span>
            {label.description ? <span className="text-xs text-muted-foreground">{label.description}</span> : <code className="w-fit rounded bg-muted px-1.5 text-xs">{scope}</code>}
          </li>
        )
      })}
    </ul>
  )
}
