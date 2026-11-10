import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Item, ItemActions, ItemContent, ItemDescription, ItemTitle } from '@/components/ui/item'
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Spinner } from '@/components/ui/spinner'
import { Switch } from '@/components/ui/switch'
import { ApiError, apiFetch } from '@/lib/api'
import { TARGET_INFO, type BindingTarget, type Policy } from '@/lib/policies'

export function BindingDialog({
  open,
  onOpenChange,
  policies,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  policies: Policy[]
}) {
  const queryClient = useQueryClient()
  const [target, setTarget] = useState<BindingTarget>('login')
  const [targetRef, setTargetRef] = useState('default')
  const [policyId, setPolicyId] = useState('')
  const [order, setOrder] = useState('0')
  const [negate, setNegate] = useState(false)
  const [failOpen, setFailOpen] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)

  const create = useMutation({
    mutationFn: () =>
      apiFetch('/api/admin/policy-bindings', {
        method: 'POST',
        body: JSON.stringify({
          target,
          targetRef: targetRef.trim(),
          policyId,
          order: Number(order),
          negate,
          failureResult: failOpen ? 'pass' : 'fail',
        }),
      }),
    onSuccess: async () => {
      toast.success('정책을 연결했습니다.')
      setFailure(null)
      onOpenChange(false)
      await queryClient.invalidateQueries({ queryKey: ['admin', 'policy-bindings'] })
    },
    onError: (cause: unknown) => setFailure(cause instanceof ApiError ? cause.message : '연결하지 못했습니다.'),
  })

  function changeTarget(next: BindingTarget) {
    setTarget(next)
    setTargetRef(next === 'application' || next === 'notification_rule' ? '' : 'default')
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    const position = Number(order)
    if (!Number.isInteger(position) || position < 0 || position > 999) {
      setFailure('순서는 0에서 999 사이의 정수여야 합니다.')
      return
    }
    create.mutate()
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !create.isPending && onOpenChange(next)}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>정책 연결</DialogTitle>
          <DialogDescription>정책이 어느 단계에서 검사될지 정합니다.</DialogDescription>
        </DialogHeader>
        <form id="binding-form" onSubmit={submit} noValidate>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="binding-target">검사할 때</FieldLabel>
              <Select value={target} onValueChange={(value) => changeTarget(value as BindingTarget)}>
                <SelectTrigger id="binding-target" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    {(Object.keys(TARGET_INFO) as BindingTarget[]).map((entry) => (
                      <SelectItem key={entry} value={entry}>
                        {TARGET_INFO[entry].label}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </Field>
            <Field>
              <FieldLabel htmlFor="binding-ref">대상</FieldLabel>
              <Input
                id="binding-ref"
                autoComplete="off"
                spellCheck={false}
                className="font-mono"
                placeholder={TARGET_INFO[target].refHint}
                value={targetRef}
                onChange={(event) => setTargetRef(event.target.value)}
              />
              <FieldDescription>{TARGET_INFO[target].refHint}</FieldDescription>
            </Field>
            <Field>
              <FieldLabel htmlFor="binding-policy">정책</FieldLabel>
              <Select value={policyId} onValueChange={setPolicyId}>
                <SelectTrigger id="binding-policy" className="w-full">
                  <SelectValue placeholder="정책 선택" />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    {policies.map((policy) => (
                      <SelectItem key={policy.id} value={policy.id}>
                        {policy.name}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </Field>
            <Field data-invalid={failure ? true : undefined}>
              <FieldLabel htmlFor="binding-order">순서</FieldLabel>
              <Input id="binding-order" type="number" inputMode="numeric" className="w-28" min={0} max={999} value={order} onChange={(event) => setOrder(event.target.value)} />
              <FieldDescription>작은 숫자부터 먼저 검사합니다.</FieldDescription>
              {failure ? <FieldError>{failure}</FieldError> : null}
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
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={create.isPending}>
            취소
          </Button>
          <Button type="submit" form="binding-form" disabled={create.isPending || !policyId || !targetRef.trim()}>
            {create.isPending ? <Spinner data-icon="inline-start" /> : null}
            연결
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
