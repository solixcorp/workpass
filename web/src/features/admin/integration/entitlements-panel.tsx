import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { PencilIcon, PlusIcon, Trash2Icon, UsersIcon } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '@/components/ui/alert-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { Textarea } from '@/components/ui/textarea'
import { ApiError, apiFetch } from '@/lib/api'
import { groupsQuery } from '@/lib/integrations'

type Entitlement = { id: string; key: string; name: string; description: string | null; groups: Array<{ id: string; name: string }>; memberCount: number }
type View = { entitlements: Entitlement[]; releaseNote: string }

const message = (error: unknown, fallback: string) => (error instanceof ApiError && /[가-힣]/.test(error.message) ? error.message : fallback)

/** The permission levels an app has (for example admin, editor, viewer) and which groups hold each. */
export function EntitlementsPanel({ slug }: { slug: string }) {
  const queryClient = useQueryClient()
  const key = ['admin', 'application', slug, 'entitlements']
  const query = useQuery({ queryKey: key, queryFn: () => apiFetch<View>(`/api/admin/applications/${slug}/entitlements`) })
  const [editing, setEditing] = useState<Entitlement | 'new' | null>(null)
  const [assigning, setAssigning] = useState<Entitlement | null>(null)
  const [removing, setRemoving] = useState<Entitlement | null>(null)
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['admin', 'application', slug] })

  const remove = useMutation({
    mutationFn: (entry: Entitlement) => apiFetch(`/api/admin/applications/${slug}/entitlements/${entry.id}`, { method: 'DELETE' }),
    onSuccess: async () => {
      toast.success('권한을 지웠습니다.')
      setRemoving(null)
      await refresh()
    },
    onError: () => toast.error('지우지 못했습니다.'),
  })

  if (query.isPending) return <Skeleton className="h-48 w-full" />
  if (query.error) {
    return (
      <Alert variant="destructive">
        <AlertDescription>권한을 불러오지 못했습니다.</AlertDescription>
      </Alert>
    )
  }
  const { entitlements, releaseNote } = query.data

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <p className="max-w-xl text-sm text-muted-foreground">앱 안에서의 권한 수준을 정의하고, 그룹에 나눠 줍니다. 사람이 이 앱을 열 수 있고 권한을 가진 그룹에 속하면 그 권한이 앱에 전달됩니다.</p>
        <Button size="sm" onClick={() => setEditing('new')}>
          <PlusIcon data-icon="inline-start" />
          권한 추가
        </Button>
      </div>
      <Alert>
        <AlertDescription>
          {releaseNote} 서버에서 사용자 속성 전달(ENABLE_ATTRIBUTE_CLAIMS)이 꺼져 있거나, ‘연동’ 화면의 이 앱 클레임 정책에서 사용자 속성이 꺼져 있거나, 속성 허용 목록에 entitlements가 없으면 전달되지 않습니다.
        </AlertDescription>
      </Alert>

      {entitlements.length === 0 ? (
        <p className="rounded-xl border border-dashed p-8 text-center text-sm text-muted-foreground">정의한 권한이 없습니다. 권한을 하나라도 만들면 이 앱으로 권한 정보가 전달되기 시작합니다.</p>
      ) : (
        <ul className="flex flex-col gap-3">
          {entitlements.map((entry) => (
            <li key={entry.id} className="flex flex-col gap-3 rounded-2xl border bg-card p-5">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="flex min-w-0 flex-col gap-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="text-sm font-semibold">{entry.name}</h3>
                    <code className="rounded bg-muted px-1.5 text-xs">{entry.key}</code>
                  </div>
                  {entry.description ? <p className="text-xs text-muted-foreground">{entry.description}</p> : null}
                </div>
                <div className="flex items-center gap-1">
                  <Button variant="ghost" size="icon-sm" aria-label={`${entry.name} 수정`} onClick={() => setEditing(entry)}>
                    <PencilIcon />
                  </Button>
                  <Button variant="ghost" size="icon-sm" aria-label={`${entry.name} 삭제`} onClick={() => setRemoving(entry)}>
                    <Trash2Icon />
                  </Button>
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {entry.groups.length ? entry.groups.map((group) => <Badge key={group.id} variant="secondary">{group.name}</Badge>) : <span className="text-xs text-muted-foreground">할당된 그룹이 없습니다.</span>}
                <Button variant="outline" size="xs" onClick={() => setAssigning(entry)}>
                  그룹 지정
                </Button>
                <span className="ml-auto flex items-center gap-1 text-xs text-muted-foreground">
                  <UsersIcon className="size-3.5" />
                  지금 {entry.memberCount.toLocaleString('ko-KR')}명이 가짐
                </span>
              </div>
            </li>
          ))}
        </ul>
      )}

      {editing ? <EntitlementDialog key={editing === 'new' ? 'new' : editing.id} slug={slug} entry={editing === 'new' ? null : editing} onClose={() => setEditing(null)} onSaved={refresh} /> : null}
      {assigning ? <GroupsDialog key={assigning.id} slug={slug} entry={assigning} onClose={() => setAssigning(null)} onSaved={refresh} /> : null}
      <AlertDialog open={removing !== null} onOpenChange={(open) => !open && !remove.isPending && setRemoving(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{removing?.name} 권한을 지울까요?</AlertDialogTitle>
            <AlertDialogDescription>그룹 지정도 함께 사라지고, 사람들의 권한 정보에서 빠집니다. 앱이 이 권한에 의존한다면 접근이 바뀔 수 있습니다.</AlertDialogDescription>
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

function EntitlementDialog({ slug, entry, onClose, onSaved }: { slug: string; entry: Entitlement | null; onClose: () => void; onSaved: () => Promise<unknown> }) {
  const [key, setKey] = useState(entry?.key ?? '')
  const [name, setName] = useState(entry?.name ?? '')
  const [description, setDescription] = useState(entry?.description ?? '')
  const [failure, setFailure] = useState<string | null>(null)

  const save = useMutation({
    mutationFn: () =>
      entry
        ? apiFetch(`/api/admin/applications/${slug}/entitlements/${entry.id}`, { method: 'PUT', body: JSON.stringify({ name: name.trim(), description: description.trim() }) })
        : apiFetch(`/api/admin/applications/${slug}/entitlements`, { method: 'POST', body: JSON.stringify({ key: key.trim(), name: name.trim(), description: description.trim() }) }),
    onSuccess: async () => {
      toast.success(entry ? '권한을 저장했습니다.' : '권한을 만들었습니다.')
      await onSaved()
      onClose()
    },
    onError: (error) => setFailure(message(error, '저장하지 못했습니다.')),
  })

  return (
    <Dialog open onOpenChange={(open) => !open && !save.isPending && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{entry ? '권한 수정' : '권한 추가'}</DialogTitle>
          <DialogDescription>앱이 이해하는 권한 이름(키)과, 관리자가 알아볼 이름을 정합니다.</DialogDescription>
        </DialogHeader>
        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="ent-key">키</FieldLabel>
            <Input id="ent-key" disabled={entry !== null} value={key} onChange={(event) => setKey(event.target.value)} placeholder="editor" autoComplete="off" spellCheck={false} />
            <FieldDescription>앱에 그대로 전달되는 값입니다. 영문 소문자, 숫자, - _ . : 만 쓰고, 만든 뒤에는 바꿀 수 없습니다.</FieldDescription>
          </Field>
          <Field>
            <FieldLabel htmlFor="ent-name">이름</FieldLabel>
            <Input id="ent-name" value={name} onChange={(event) => setName(event.target.value)} placeholder="편집자" />
          </Field>
          <Field>
            <FieldLabel htmlFor="ent-desc">설명</FieldLabel>
            <Textarea id="ent-desc" rows={2} value={description} onChange={(event) => setDescription(event.target.value)} />
          </Field>
        </FieldGroup>
        {failure ? (
          <Alert variant="destructive">
            <AlertDescription>{failure}</AlertDescription>
          </Alert>
        ) : null}
        <DialogFooter>
          <Button variant="outline" disabled={save.isPending} onClick={onClose}>취소</Button>
          <Button disabled={save.isPending || !name.trim() || (!entry && !key.trim())} onClick={() => { setFailure(null); save.mutate() }}>
            {save.isPending ? <Spinner data-icon="inline-start" /> : null}
            저장
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function GroupsDialog({ slug, entry, onClose, onSaved }: { slug: string; entry: Entitlement; onClose: () => void; onSaved: () => Promise<unknown> }) {
  const groups = useQuery(groupsQuery)
  const [picked, setPicked] = useState(entry.groups.map((group) => group.id))
  const [failure, setFailure] = useState<string | null>(null)
  const save = useMutation({
    mutationFn: () => apiFetch(`/api/admin/applications/${slug}/entitlements/${entry.id}/groups`, { method: 'PUT', body: JSON.stringify({ groupIds: picked }) }),
    onSuccess: async () => {
      toast.success('그룹을 저장했습니다.')
      await onSaved()
      onClose()
    },
    onError: (error) => setFailure(message(error, '저장하지 못했습니다.')),
  })
  return (
    <Dialog open onOpenChange={(open) => !open && !save.isPending && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{entry.name} 권한을 줄 그룹</DialogTitle>
          <DialogDescription>이 그룹에 속하고 앱을 열 수 있는 사람이 이 권한을 가집니다.</DialogDescription>
        </DialogHeader>
        <div className="flex max-h-72 flex-col gap-2 overflow-y-auto">
          {groups.isPending ? <Skeleton className="h-20 w-full" /> : (groups.data ?? []).length === 0 ? <p className="text-sm text-muted-foreground">그룹이 없습니다.</p> : (groups.data ?? []).map((group) => (
            <Field key={group.id} orientation="horizontal">
              <Checkbox id={`ent-group-${group.id}`} checked={picked.includes(group.id)} onCheckedChange={(on) => setPicked(on === true ? [...picked, group.id] : picked.filter((id) => id !== group.id))} />
              <FieldLabel htmlFor={`ent-group-${group.id}`}>{group.name}</FieldLabel>
            </Field>
          ))}
        </div>
        {failure ? (
          <Alert variant="destructive">
            <AlertDescription>{failure}</AlertDescription>
          </Alert>
        ) : null}
        <DialogFooter>
          <Button variant="outline" disabled={save.isPending} onClick={onClose}>취소</Button>
          <Button disabled={save.isPending} onClick={() => { setFailure(null); save.mutate() }}>
            {save.isPending ? <Spinner data-icon="inline-start" /> : null}
            저장
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
