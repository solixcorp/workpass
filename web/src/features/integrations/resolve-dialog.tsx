import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Field, FieldLabel } from '@/components/ui/field'
import { Spinner } from '@/components/ui/spinner'
import { Textarea } from '@/components/ui/textarea'
import { ApiError, apiFetch } from '@/lib/api'
import type { ScimOperation } from './types'

/** The administrator has looked at the other system and says what happened, so this person can be sent again. */
export function ResolveDialog({ operation, onClose }: { operation: ScimOperation | null; onClose: () => void }) {
  const queryClient = useQueryClient()
  const [note, setNote] = useState('')
  const [failure, setFailure] = useState<string | null>(null)
  const resolve = useMutation({
    mutationFn: () => apiFetch(`/api/admin/scim-operations/${operation!.id}/resolve`, { method: 'POST', body: JSON.stringify({ note: note.trim() || undefined }) }),
    onSuccess: async () => {
      toast.success('확인했다고 표시했습니다. 이 사용자를 다시 보낼 수 있습니다.')
      setNote('')
      await queryClient.invalidateQueries({ queryKey: ['admin', 'integrations'] })
      onClose()
    },
    onError: (error) => setFailure(error instanceof ApiError && /[가-힣]/.test(error.message) ? error.message : '처리하지 못했습니다.'),
  })
  return (
    <Dialog open={operation !== null} onOpenChange={(open) => !open && !resolve.isPending && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>결과를 확인했나요?</DialogTitle>
          <DialogDescription>
            {operation?.abandoned ? '이 작업은 오래 끝나지 않아 중단된 것으로 처리되었습니다. ' : '응답을 받지 못해 외부 시스템에 반영됐는지 알 수 없습니다. '}
            외부 시스템에서 {operation?.user_name ?? '이 사용자'}의 상태를 직접 확인한 뒤 누르세요. 누르면 이 작업은 실패로 정리되고 같은 사용자를 다시 보낼 수 있습니다.
          </DialogDescription>
        </DialogHeader>
        <Field>
          <FieldLabel htmlFor="resolve-note">메모 (선택)</FieldLabel>
          <Textarea id="resolve-note" rows={2} maxLength={500} value={note} onChange={(event) => setNote(event.target.value)} placeholder="예: 외부 시스템에서 계정이 이미 만들어져 있음을 확인" />
        </Field>
        {failure ? (
          <Alert variant="destructive">
            <AlertDescription>{failure}</AlertDescription>
          </Alert>
        ) : null}
        <DialogFooter>
          <Button variant="outline" disabled={resolve.isPending} onClick={onClose}>취소</Button>
          <Button disabled={resolve.isPending} onClick={() => { setFailure(null); resolve.mutate() }}>
            {resolve.isPending ? <Spinner data-icon="inline-start" /> : null}
            확인했음
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
