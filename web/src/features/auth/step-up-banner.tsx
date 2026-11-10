import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ShieldAlertIcon } from 'lucide-react'
import { useState } from 'react'
import { Alert, AlertAction, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { stepUpQuery } from '@/lib/queries'
import { TwoFactorForm } from './two-factor-form'

/**
 * Surfaces an open step-up challenge for the acting session. SSO issuance
 * stays withheld by the backend until a second factor is verified; this
 * banner only lets the user complete it without leaving the portal.
 */
export function StepUpBanner() {
  const queryClient = useQueryClient()
  const { data } = useQuery(stepUpQuery)
  const [open, setOpen] = useState(false)

  if (!data?.required) return null

  const { ui } = data
  const expired = data.state === 'expired'
  const canVerify = ui.methods.length > 0

  return (
    <>
      <Alert>
        <ShieldAlertIcon />
        <AlertTitle>{ui.banner.title}</AlertTitle>
        <AlertDescription>
          {expired ? ui.banner.expiredDescription : ui.banner.description}
        </AlertDescription>
        {!expired && canVerify ? (
          <AlertAction>
            <Button size="sm" onClick={() => setOpen(true)}>
              {ui.banner.action}
            </Button>
          </AlertAction>
        ) : null}
      </Alert>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle>{ui.banner.dialogTitle}</DialogTitle>
            <DialogDescription>{ui.banner.dialogDescription}</DialogDescription>
          </DialogHeader>
          <TwoFactorForm
            ui={ui}
            onVerified={async () => {
              setOpen(false)
              await queryClient.invalidateQueries({ queryKey: ['step-up'] })
            }}
          />
        </DialogContent>
      </Dialog>
    </>
  )
}
