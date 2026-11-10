import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { PlusIcon, Trash2Icon } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from '@/components/ui/empty'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { ApiError, apiFetch } from '@/lib/api'
import { summarize, TARGET_INFO, TYPE_INFO, type Binding, type Policy } from '@/lib/policies'
import { BindingDialog } from './policy-binding-dialog'
import { NotificationRules } from './notification-rules'
import { PolicyDialog } from './policy-dialog'

const policiesKey = ['admin', 'policies'] as const
const bindingsKey = ['admin', 'policy-bindings'] as const

export function PoliciesPage() {
  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-8">
      <h1 className="text-2xl font-semibold">정책</h1>
      <PolicyList />
      <BindingList />
      <NotificationRules />
    </div>
  )
}

function PolicyList() {
  const queryClient = useQueryClient()
  const { data, isPending, error } = useQuery({
    queryKey: policiesKey,
    queryFn: async () => (await apiFetch<{ policies: Policy[] }>('/api/admin/policies')).policies,
  })
  const [dialog, setDialog] = useState<{ policy: Policy | null } | null>(null)
  const [pendingDelete, setPendingDelete] = useState<Policy | null>(null)

  const toggle = useMutation({
    mutationFn: ({ policy, enabled }: { policy: Policy; enabled: boolean }) =>
      apiFetch(`/api/admin/policies/${policy.id}`, { method: 'PUT', body: JSON.stringify({ enabled }) }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: policiesKey }),
    onError: () => toast.error('상태를 바꾸지 못했습니다.'),
  })

  const remove = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/admin/policies/${id}`, { method: 'DELETE' }),
    onSuccess: async () => {
      setPendingDelete(null)
      toast.success('정책을 삭제했습니다.')
      await queryClient.invalidateQueries({ queryKey: policiesKey })
    },
    onError: (cause: unknown) => {
      setPendingDelete(null)
      toast.error(cause instanceof ApiError && cause.status === 409 ? '아직 연결된 정책이라 삭제할 수 없습니다. 먼저 연결을 해제하세요.' : '정책을 삭제하지 못했습니다.')
    },
  })

  return (
    <section className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-4">
        <div className="flex flex-col gap-1">
          <h2 className="text-sm font-medium text-muted-foreground">정책</h2>
          <p className="text-sm text-muted-foreground">판정 규칙입니다. 만든 뒤 아래에서 로그인이나 앱에 연결해야 적용됩니다.</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => setDialog({ policy: null })}>
          <PlusIcon data-icon="inline-start" />정책 추가
        </Button>
      </div>
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>정책을 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : isPending ? (
        <Skeleton className="h-24 rounded-xl" />
      ) : data!.length === 0 ? (
        <Empty>
          <EmptyHeader>
            <EmptyTitle>정책이 없습니다</EmptyTitle>
            <EmptyDescription>평판, 위치, 비밀번호 만료 같은 규칙을 만들어 로그인이나 앱에 연결할 수 있습니다.</EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>이름</TableHead>
                <TableHead>유형</TableHead>
                <TableHead>내용</TableHead>
                <TableHead className="sticky right-0 bg-background">사용</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data!.map((policy) => (
                <TableRow key={policy.id}>
                  <TableCell className="font-medium">
                    {policy.name}
                    {policy.name === 'workpass-password-rules' ? (
                      <span className="block text-xs font-normal text-muted-foreground">설정 화면의 비밀번호 규칙이 관리합니다</span>
                    ) : null}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{TYPE_INFO[policy.type]?.label ?? policy.type}</Badge>
                  </TableCell>
                  <TableCell className="max-w-sm truncate text-muted-foreground">{summarize(policy)}</TableCell>
                  <TableCell className="whitespace-nowrap sticky right-0 bg-background">
                    <div className="flex items-center justify-end gap-2">
                      <Switch
                        aria-label={`${policy.name} 사용`}
                        checked={policy.enabled}
                        disabled={toggle.isPending}
                        onCheckedChange={(enabled) => toggle.mutate({ policy, enabled })}
                      />
                      <Button variant="outline" size="sm" onClick={() => setDialog({ policy })}>
                        편집
                      </Button>
                      <Button variant="ghost" size="icon-sm" aria-label={`${policy.name} 삭제`} onClick={() => setPendingDelete(policy)}>
                        <Trash2Icon />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      <PolicyDialog state={dialog} onClose={() => setDialog(null)} />
      <AlertDialog open={pendingDelete !== null} onOpenChange={(open) => !open && setPendingDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{pendingDelete?.name} 정책을 삭제할까요?</AlertDialogTitle>
            <AlertDialogDescription>연결된 곳이 있으면 삭제되지 않습니다. 먼저 연결을 해제하세요.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>취소</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={remove.isPending}
              onClick={(event) => {
                event.preventDefault()
                if (pendingDelete) remove.mutate(pendingDelete.id)
              }}
            >
              삭제
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  )
}

function BindingList() {
  const queryClient = useQueryClient()
  const policies = useQuery({
    queryKey: policiesKey,
    queryFn: async () => (await apiFetch<{ policies: Policy[] }>('/api/admin/policies')).policies,
  })
  const { data, isPending, error } = useQuery({
    queryKey: bindingsKey,
    queryFn: async () => (await apiFetch<{ bindings: Binding[] }>('/api/admin/policy-bindings')).bindings,
  })
  const [open, setOpen] = useState(false)

  const toggle = useMutation({
    mutationFn: ({ binding, enabled }: { binding: Binding; enabled: boolean }) =>
      apiFetch(`/api/admin/policy-bindings/${binding.id}`, { method: 'PATCH', body: JSON.stringify({ enabled }) }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: bindingsKey }),
    onError: () => toast.error('상태를 바꾸지 못했습니다.'),
  })

  const remove = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/admin/policy-bindings/${id}`, { method: 'DELETE' }),
    onSuccess: async () => {
      toast.success('연결을 해제했습니다.')
      await queryClient.invalidateQueries({ queryKey: bindingsKey })
    },
    onError: () => toast.error('해제하지 못했습니다.'),
  })

  return (
    <section className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-4">
        <div className="flex flex-col gap-1">
          <h2 className="text-sm font-medium text-muted-foreground">연결</h2>
          <p className="text-sm text-muted-foreground">
            정책이 언제 검사되는지 정합니다. 같은 대상에 여러 개를 연결하면 순서대로 검사합니다.
          </p>
        </div>
        <Button variant="outline" size="sm" disabled={(policies.data ?? []).length === 0} onClick={() => setOpen(true)}>
          <PlusIcon data-icon="inline-start" />연결 추가
        </Button>
      </div>
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>연결을 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : isPending ? (
        <Skeleton className="h-24 rounded-xl" />
      ) : data!.length === 0 ? (
        <p className="text-sm text-muted-foreground">연결된 정책이 없습니다.</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>대상</TableHead>
                <TableHead>정책</TableHead>
                <TableHead>순서</TableHead>
                <TableHead>동작</TableHead>
                <TableHead className="sticky right-0 bg-background">사용</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data!.map((binding) => (
                <TableRow key={binding.id}>
                  <TableCell>
                    <div className="flex flex-col">
                      <span className="font-medium">{TARGET_INFO[binding.target]?.label ?? binding.target}</span>
                      <span className="font-mono text-xs text-muted-foreground">{binding.targetRef}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    {binding.policyName ?? (binding.bindGroupId ? '그룹 조건' : binding.bindUserId ? '사용자 조건' : '—')}
                  </TableCell>
                  <TableCell className="tabular-nums">{binding.orderIndex}</TableCell>
                  <TableCell className="text-muted-foreground">
                    {binding.negate ? '결과 뒤집기 · ' : ''}오류 시 {binding.failureResult === 'pass' ? '통과' : '거절'}
                  </TableCell>
                  <TableCell className="whitespace-nowrap sticky right-0 bg-background">
                    <div className="flex items-center justify-end gap-2">
                      <Switch
                        aria-label="연결 사용"
                        checked={binding.enabled}
                        disabled={toggle.isPending}
                        onCheckedChange={(enabled) => toggle.mutate({ binding, enabled })}
                      />
                      <Button variant="ghost" size="icon-sm" aria-label="연결 해제" onClick={() => remove.mutate(binding.id)}>
                        <Trash2Icon />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      <BindingDialog open={open} onOpenChange={setOpen} policies={policies.data ?? []} />
    </section>
  )
}
