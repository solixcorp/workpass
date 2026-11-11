import type { ReactNode } from 'react'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog'
import { Spinner } from '@/components/ui/spinner'

export type ConfirmDetail = { label: string; value: ReactNode }

/**
 * Asks once more before something that cannot be undone. The details list shows what exactly is about to be
 * affected so the person can notice a mistake (the wrong device, an unfamiliar place) before confirming.
 */
export function ConfirmDialog({
  open,
  title,
  description,
  details,
  confirmLabel,
  pending,
  onConfirm,
  onCancel,
}: {
  open: boolean
  title: string
  description: ReactNode
  details?: ConfirmDetail[]
  confirmLabel: string
  pending: boolean
  onConfirm: () => void
  onCancel: () => void
}) {
  return (
    <AlertDialog open={open} onOpenChange={(next) => !next && !pending && onCancel()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>
        {details?.length ? (
          <dl className="grid grid-cols-[6rem_1fr] gap-x-3 gap-y-1.5 rounded-lg border bg-muted/40 px-3 py-2.5 text-sm">
            {details.map((detail) => (
              <div key={detail.label} className="contents">
                <dt className="text-muted-foreground">{detail.label}</dt>
                <dd className="break-words">{detail.value}</dd>
              </div>
            ))}
          </dl>
        ) : null}
        <AlertDialogFooter>
          <AlertDialogCancel disabled={pending}>취소</AlertDialogCancel>
          <AlertDialogAction
            variant="destructive"
            disabled={pending}
            onClick={(event) => {
              event.preventDefault()
              onConfirm()
            }}
          >
            {pending ? <Spinner data-icon="inline-start" /> : null}
            {confirmLabel}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}

/** Wraps one button: pressing it opens a confirmation first, and only "확인" runs the action. */
export function ConfirmAction({
  title,
  description,
  details,
  confirmLabel,
  onConfirm,
  children,
}: {
  title: string
  description: ReactNode
  details?: ConfirmDetail[]
  confirmLabel: string
  onConfirm: () => void
  children: ReactNode
}) {
  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>{children}</AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>
        {details?.length ? (
          <dl className="grid grid-cols-[6rem_1fr] gap-x-3 gap-y-1.5 rounded-lg border bg-muted/40 px-3 py-2.5 text-sm">
            {details.map((detail) => (
              <div key={detail.label} className="contents">
                <dt className="text-muted-foreground">{detail.label}</dt>
                <dd className="break-words">{detail.value}</dd>
              </div>
            ))}
          </dl>
        ) : null}
        <AlertDialogFooter>
          <AlertDialogCancel>취소</AlertDialogCancel>
          <AlertDialogAction variant="destructive" onClick={onConfirm}>
            {confirmLabel}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
