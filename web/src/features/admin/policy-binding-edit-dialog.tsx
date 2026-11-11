import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Item, ItemActions, ItemContent, ItemDescription, ItemTitle } from '@/components/ui/item'
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Spinner } from '@/components/ui/spinner'
import { Switch } from '@/components/ui/switch'
import { ApiError, apiFetch } from '@/lib/api'
import type { Binding } from '@/lib/policies'

/** Change how an existing policy link behaves without removing and re-creating it. */
export function BindingEditDialog({ binding, onClose }: { binding: Binding | null; onClose: () => void }) {
  return (
    <Dialog open={binding !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-md">{binding ? <EditForm key={binding.id} binding={binding} onClose={onClose} /> : null}</DialogContent>
    </Dialog>
  )
}

function EditForm({ binding, onClose }: { binding: Binding; onClose: () => void }) {
  const queryClient = useQueryClient()
  const [order, setOrder] = useState(String(binding.orderIndex))
  const [mode, setMode] = useState<Binding['mode']>(binding.mode)
  const [negate, setNegate] = useState(binding.negate)
  const [failOpen, setFailOpen] = useState(binding.failureResult === 'pass')
  const [failure, setFailure] = useState<string | null>(null)

  const save = useMutation({
    mutationFn: () =>
      apiFetch(`/api/admin/policy-bindings/${binding.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ order: Number(order), mode, negate, failureResult: failOpen ? 'pass' : 'fail' }),
      }),
    onSuccess: async () => {
      toast.success('연결 설정을 저장했습니다.')
      await queryClient.invalidateQueries({ queryKey: ['admin', 'policy-bindings'] })
      onClose()
    },
    onError: (error) => setFailure(error instanceof ApiError && /[가-힣]/.test(error.message) ? error.message : '저장하지 못했습니다.'),
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    const value = Number(order)
    if (!Number.isInteger(value) || value < 0 || value > 999) {
      setFailure('순서는 0에서 999 사이의 정수여야 합니다.')
      return
    }
    save.mutate()
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>연결 설정 수정</DialogTitle>
        <DialogDescription>{binding.policyName ?? '정책'} · {binding.targetRef}</DialogDescription>
      </DialogHeader>
      <form id="binding-edit-form" onSubmit={submit} noValidate>
        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="binding-edit-order">순서</FieldLabel>
            <Input id="binding-edit-order" type="number" inputMode="numeric" className="w-28" min={0} max={999} value={order} onChange={(event) => setOrder(event.target.value)} />
            <FieldDescription>작은 숫자부터 먼저 검사합니다.</FieldDescription>
          </Field>
          <Field>
            <FieldLabel htmlFor="binding-edit-mode">여러 조건일 때</FieldLabel>
            <Select value={mode} onValueChange={(value) => setMode(value as Binding['mode'])}>
              <SelectTrigger id="binding-edit-mode" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="all">모두 맞아야 함</SelectItem>
                  <SelectItem value="any">하나만 맞아도 됨</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
          </Field>
          <Item variant="outline" size="sm">
            <ItemContent>
              <ItemTitle>결과 뒤집기</ItemTitle>
              <ItemDescription>정책이 통과하면 거절로, 거절하면 통과로 봅니다.</ItemDescription>
            </ItemContent>
            <ItemActions>
              <Switch aria-label="결과 뒤집기" checked={negate} onCheckedChange={setNegate} />
            </ItemActions>
          </Item>
          <Item variant="outline" size="sm">
            <ItemContent>
              <ItemTitle>정책 오류 때 통과시키기</ItemTitle>
              <ItemDescription>정책을 평가하다 오류가 나면 통과로 봅니다. 꺼 두면 오류는 거절입니다.</ItemDescription>
            </ItemContent>
            <ItemActions>
              <Switch aria-label="정책 오류 때 통과" checked={failOpen} onCheckedChange={setFailOpen} />
            </ItemActions>
          </Item>
        </FieldGroup>
      </form>
      {failure ? (
        <Alert variant="destructive">
          <AlertDescription>{failure}</AlertDescription>
        </Alert>
      ) : null}
      <DialogFooter>
        <Button type="button" variant="outline" disabled={save.isPending} onClick={onClose}>
          취소
        </Button>
        <Button type="submit" form="binding-edit-form" disabled={save.isPending}>
          {save.isPending ? <Spinner data-icon="inline-start" /> : null}
          저장
        </Button>
      </DialogFooter>
    </>
  )
}
