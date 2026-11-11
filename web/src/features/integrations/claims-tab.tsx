import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { PencilIcon, PlusIcon, Trash2Icon } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '@/components/ui/alert-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Field, FieldContent, FieldDescription, FieldLabel } from '@/components/ui/field'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { Switch } from '@/components/ui/switch'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Textarea } from '@/components/ui/textarea'
import { apiFetch } from '@/lib/api'
import type { ClaimPolicy, UnpolicedApp } from './types'

type Editing = { subject: string; name: string; policy: Omit<ClaimPolicy, 'subject' | 'applicationName' | 'applicationSlug'>; isNew: boolean }

const KINDS: Array<{ key: 'allowAccountClaims' | 'allowUserAttributes' | 'allowAccountAttributes' | 'allowGroupAttributes'; label: string; description: string }> = [
  { key: 'allowAccountClaims', label: '계정 정보', description: '로그인에 쓴 계정(조직)을 토큰에 담습니다.' },
  { key: 'allowUserAttributes', label: '사용자 속성', description: '관리자가 사용자에게 저장한 속성을 담습니다.' },
  { key: 'allowAccountAttributes', label: '계정 속성', description: '계정(조직)에 저장한 속성을 담습니다.' },
  { key: 'allowGroupAttributes', label: '그룹 속성', description: '사용자가 속한 그룹의 속성을 담습니다.' },
]

/** What each app is allowed to be told about a person, on top of the server-wide switches. */
export function ClaimsTab() {
  const queryClient = useQueryClient()
  const query = useQuery({ queryKey: ['admin', 'integrations', 'claims'], queryFn: () => apiFetch<{ policies: ClaimPolicy[]; applicationsWithoutPolicy: UnpolicedApp[] }>('/api/admin/claim-release-policies') })
  const [editing, setEditing] = useState<Editing | null>(null)
  const [removing, setRemoving] = useState<ClaimPolicy | null>(null)
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['admin', 'integrations'] })

  const remove = useMutation({
    mutationFn: (policy: ClaimPolicy) => apiFetch(`/api/admin/claim-release-policies/${encodeURIComponent(policy.subject)}`, { method: 'DELETE' }),
    onSuccess: async () => {
      toast.success('정책을 지웠습니다. 서버 기본값이 적용됩니다.')
      setRemoving(null)
      await refresh()
    },
    onError: () => toast.error('지우지 못했습니다.'),
  })

  if (query.isPending) return <Skeleton className="h-48 w-full" />
  if (query.error) {
    return (
      <Alert variant="destructive">
        <AlertDescription>정책을 불러오지 못했습니다.</AlertDescription>
      </Alert>
    )
  }
  const { policies, applicationsWithoutPolicy } = query.data
  const summary = (policy: Pick<ClaimPolicy, 'allowAccountClaims' | 'allowUserAttributes' | 'allowAccountAttributes' | 'allowGroupAttributes'>) =>
    KINDS.filter((kind) => policy[kind.key]).map((kind) => kind.label)

  return (
    <div className="flex flex-col gap-8">
      <section className="flex flex-col gap-3">
        <h2 className="text-sm font-semibold">앱별 정책</h2>
        <p className="text-xs text-muted-foreground">정책은 서버에서 켜 둔 범위 안에서만 좁힐 수 있고, 넓힐 수는 없습니다. 정책이 없는 앱에는 아래 ‘정책이 없는 앱’의 기본값이 적용됩니다.</p>
        {policies.length === 0 ? (
          <p className="rounded-xl border border-dashed p-8 text-center text-sm text-muted-foreground">앱별 정책이 없습니다.</p>
        ) : (
          <div className="overflow-x-auto rounded-xl border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>앱</TableHead>
                  <TableHead>내보내는 정보</TableHead>
                  <TableHead>속성 허용 목록</TableHead>
                  <TableHead className="w-24" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {policies.map((policy) => (
                  <TableRow key={policy.subject}>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-medium">{policy.applicationName ?? '이름 없는 앱'}</span>
                        <span className="font-mono text-xs text-muted-foreground">{policy.subject}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {summary(policy).length ? summary(policy).map((label) => <Badge key={label} variant="secondary">{label}</Badge>) : <span className="text-xs text-muted-foreground">아무것도 내보내지 않음</span>}
                      </div>
                    </TableCell>
                    <TableCell className="max-w-56 truncate text-xs text-muted-foreground">{policy.attributeAllowlist ? policy.attributeAllowlist.join(', ') || '(비어 있음)' : '제한 없음'}</TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="icon-sm" aria-label="수정" onClick={() => setEditing({ subject: policy.subject, name: policy.applicationName ?? policy.subject, policy, isNew: false })}>
                        <PencilIcon />
                      </Button>
                      <Button variant="ghost" size="icon-sm" aria-label="삭제" onClick={() => setRemoving(policy)}>
                        <Trash2Icon />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </section>

      <section className="flex flex-col gap-3">
        <h2 className="text-sm font-semibold">정책이 없는 앱</h2>
        {applicationsWithoutPolicy.length === 0 ? (
          <p className="text-sm text-muted-foreground">모든 앱에 정책이 있습니다.</p>
        ) : (
          <div className="overflow-x-auto rounded-xl border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>앱</TableHead>
                  <TableHead>지금 적용되는 기본값</TableHead>
                  <TableHead className="w-28" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {applicationsWithoutPolicy.map((app) => (
                  <TableRow key={app.subject}>
                    <TableCell className="font-medium">{app.applicationName}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {summary(app.defaults).length ? summary(app.defaults).map((label) => <Badge key={label} variant="outline">{label}</Badge>) : <span className="text-xs text-muted-foreground">아무것도 내보내지 않음</span>}
                      </div>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button variant="outline" size="sm" onClick={() => setEditing({ subject: app.subject, name: app.applicationName, policy: app.defaults, isNew: true })}>
                        <PlusIcon data-icon="inline-start" />
                        정책 만들기
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </section>

      {editing ? <PolicyDialog key={editing.subject} editing={editing} onClose={() => setEditing(null)} onSaved={refresh} /> : null}
      <AlertDialog open={removing !== null} onOpenChange={(open) => !open && !remove.isPending && setRemoving(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{removing?.applicationName ?? '이 앱'}의 정책을 지울까요?</AlertDialogTitle>
            <AlertDialogDescription>지우면 서버 기본값이 적용되어, 앱에 내보내는 정보가 바뀔 수 있습니다.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={remove.isPending}>취소</AlertDialogCancel>
            <AlertDialogAction variant="destructive" disabled={remove.isPending} onClick={(event) => { event.preventDefault(); if (removing) remove.mutate(removing) }}>
              지우기
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

function PolicyDialog({ editing, onClose, onSaved }: { editing: Editing; onClose: () => void; onSaved: () => Promise<unknown> }) {
  const [flags, setFlags] = useState(editing.policy)
  const [limited, setLimited] = useState(editing.policy.attributeAllowlist !== null)
  const [allowlist, setAllowlist] = useState((editing.policy.attributeAllowlist ?? []).join('\n'))
  const [failure, setFailure] = useState<string | null>(null)

  const save = useMutation({
    mutationFn: () =>
      apiFetch(`/api/admin/claim-release-policies/${encodeURIComponent(editing.subject)}`, {
        method: 'PUT',
        body: JSON.stringify({
          allowAccountClaims: flags.allowAccountClaims,
          allowUserAttributes: flags.allowUserAttributes,
          allowAccountAttributes: flags.allowAccountAttributes,
          allowGroupAttributes: flags.allowGroupAttributes,
          attributeAllowlist: limited ? allowlist.split(/[\s,]+/).filter(Boolean) : null,
        }),
      }),
    onSuccess: async () => {
      toast.success('정책을 저장했습니다.')
      await onSaved()
      onClose()
    },
    onError: () => setFailure('저장하지 못했습니다. 속성 이름을 확인하세요.'),
  })

  return (
    <Dialog open onOpenChange={(open) => !open && !save.isPending && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{editing.name} 클레임 정책</DialogTitle>
          <DialogDescription>이 앱에 내보낼 수 있는 정보를 고릅니다. 서버에서 꺼 둔 종류는 여기서 켜도 나가지 않습니다.</DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          {KINDS.map((kind) => (
            <Field key={kind.key} orientation="horizontal">
              <FieldContent>
                <FieldLabel htmlFor={`claim-${kind.key}`}>{kind.label}</FieldLabel>
                <FieldDescription>{kind.description}</FieldDescription>
              </FieldContent>
              <Switch id={`claim-${kind.key}`} checked={flags[kind.key]} onCheckedChange={(on) => setFlags({ ...flags, [kind.key]: on })} />
            </Field>
          ))}
          <Field orientation="horizontal">
            <FieldContent>
              <FieldLabel htmlFor="claim-limited">속성 이름 제한</FieldLabel>
              <FieldDescription>켜면 아래 목록에 있는 속성만 내보냅니다. 끄면 제한이 없습니다.</FieldDescription>
            </FieldContent>
            <Switch id="claim-limited" checked={limited} onCheckedChange={setLimited} />
          </Field>
          {limited ? <Textarea aria-label="허용할 속성 이름" rows={4} placeholder={'한 줄에 하나씩\n예: department'} value={allowlist} onChange={(event) => setAllowlist(event.target.value)} /> : null}
          {failure ? (
            <Alert variant="destructive">
              <AlertDescription>{failure}</AlertDescription>
            </Alert>
          ) : null}
        </div>
        <DialogFooter>
          <Button variant="outline" disabled={save.isPending} onClick={onClose}>
            취소
          </Button>
          <Button disabled={save.isPending} onClick={() => { setFailure(null); save.mutate() }}>
            {save.isPending ? <Spinner data-icon="inline-start" /> : null}
            저장
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
