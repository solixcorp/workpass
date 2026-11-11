import { ConfirmAction } from '@/components/confirm-dialog'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { PencilIcon, PlusIcon, Trash2Icon } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Field, FieldLabel } from '@/components/ui/field'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Spinner } from '@/components/ui/spinner'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { ApiError, apiFetch } from '@/lib/api'
import type { LocationView, Place } from './types'

type Target =
  | { kind: 'group'; id: string; label: string; placeIds: string[] }
  | { kind: 'app'; id: string; label: string; placeIds: string[]; mode: 'observe' | 'enforce' }

function PlaceBadges({ ids, places }: { ids: string[]; places: Place[] }) {
  const names = ids.map((id) => places.find((place) => place.id === id)?.name).filter(Boolean) as string[]
  return (
    <div className="flex flex-wrap gap-1">
      {names.length ? names.map((name) => <Badge key={name} variant="secondary">{name}</Badge>) : <span className="text-xs text-muted-foreground">없음</span>}
    </div>
  )
}

/** Group-specific and app-specific places, kept beside the organization-wide ones. */
export function ScopeRules({ view }: { view: LocationView }) {
  const queryClient = useQueryClient()
  const [editing, setEditing] = useState<Target | null>(null)
  const [picking, setPicking] = useState<'group' | 'app' | null>(null)
  const [pickedId, setPickedId] = useState('')
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['admin', 'location'] })

  const groupRules = view.groupRules ?? []
  const appRules = view.appRules ?? []
  const freeGroups = view.groups.filter((group) => !groupRules.some((rule) => rule.groupId === group.id))
  const freeApps = (view.applications ?? []).filter((app) => !appRules.some((rule) => rule.subject === app.subject))
  const enabledPlaces = view.places.filter((place) => place.enabled)

  const remove = useMutation({
    mutationFn: (target: Target) => apiFetch(target.kind === 'group' ? `/api/admin/location/groups/${target.id}` : `/api/admin/location/apps/${encodeURIComponent(target.id)}`, { method: 'DELETE' }),
    onSuccess: async () => {
      toast.success('규칙을 지웠습니다.')
      await refresh()
    },
    onError: () => toast.error('지우지 못했습니다.'),
  })

  function startNew(kind: 'group' | 'app') {
    if (!pickedId) return
    if (kind === 'group') setEditing({ kind, id: pickedId, label: view.groups.find((group) => group.id === pickedId)?.name ?? pickedId, placeIds: [] })
    else setEditing({ kind, id: pickedId, label: (view.applications ?? []).find((app) => app.subject === pickedId)?.name ?? pickedId, placeIds: [], mode: 'observe' })
    setPicking(null)
    setPickedId('')
  }

  return (
    <>
      <section className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-col gap-1">
            <h2 className="text-sm font-semibold">그룹별 장소</h2>
            <p className="max-w-xl text-xs text-muted-foreground">그룹에 자기 장소를 정해 주면, 그 그룹 사람들은 조직 전체 장소 대신 이 장소들 근처에서만 로그인할 수 있습니다. 조직 전체 정책이 꺼져 있으면 적용되지 않습니다.</p>
          </div>
          <Button size="sm" variant="outline" disabled={freeGroups.length === 0 || enabledPlaces.length === 0} onClick={() => setPicking('group')}>
            <PlusIcon data-icon="inline-start" />
            그룹 규칙 추가
          </Button>
        </div>
        {groupRules.length === 0 ? (
          <p className="rounded-xl border border-dashed p-6 text-center text-sm text-muted-foreground">그룹별 규칙이 없습니다.</p>
        ) : (
          <div className="overflow-x-auto rounded-xl border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>그룹</TableHead>
                  <TableHead>허용 장소</TableHead>
                  <TableHead className="w-24" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {groupRules.map((rule) => (
                  <TableRow key={rule.groupId}>
                    <TableCell className="font-medium">{rule.groupName}</TableCell>
                    <TableCell><PlaceBadges ids={rule.placeIds} places={view.places} /></TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="icon-sm" aria-label={`${rule.groupName} 수정`} onClick={() => setEditing({ kind: 'group', id: rule.groupId, label: rule.groupName, placeIds: rule.placeIds })}>
                        <PencilIcon />
                      </Button>
                      <ConfirmAction
                        title="이 그룹의 장소 규칙을 삭제할까요?"
                        description="삭제하면 이 그룹은 조직 전체 장소 정책만 따릅니다."
                        details={[{ label: '그룹', value: rule.groupName }]}
                        confirmLabel="삭제"
                        onConfirm={() => remove.mutate({ kind: 'group', id: rule.groupId, label: rule.groupName, placeIds: [] })}
                      >
                        <Button variant="ghost" size="icon-sm" aria-label={`${rule.groupName} 규칙 삭제`} disabled={remove.isPending}>
                          <Trash2Icon />
                        </Button>
                      </ConfirmAction>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </section>

      <section className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-col gap-1">
            <h2 className="text-sm font-semibold">앱별 장소</h2>
            <p className="max-w-xl text-xs text-muted-foreground">특정 앱은 지정한 장소 근처에서만 열 수 있게 합니다. 조직 전체 정책과 별개로 앱마다 ‘기록만’ 또는 ‘적용’을 고릅니다.</p>
          </div>
          <Button size="sm" variant="outline" disabled={freeApps.length === 0 || enabledPlaces.length === 0} onClick={() => setPicking('app')}>
            <PlusIcon data-icon="inline-start" />
            앱 규칙 추가
          </Button>
        </div>
        {appRules.length === 0 ? (
          <p className="rounded-xl border border-dashed p-6 text-center text-sm text-muted-foreground">앱별 규칙이 없습니다.</p>
        ) : (
          <div className="overflow-x-auto rounded-xl border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>앱</TableHead>
                  <TableHead>허용 장소</TableHead>
                  <TableHead>방식</TableHead>
                  <TableHead className="w-24" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {appRules.map((rule) => (
                  <TableRow key={rule.subject}>
                    <TableCell className="font-medium">{rule.applicationName ?? rule.subject}</TableCell>
                    <TableCell><PlaceBadges ids={rule.placeIds} places={view.places} /></TableCell>
                    <TableCell>
                      <Badge variant={rule.mode === 'enforce' ? 'default' : 'secondary'}>{rule.mode === 'enforce' ? '적용' : '기록만'}</Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="icon-sm" aria-label={`${rule.applicationName ?? rule.subject} 수정`} onClick={() => setEditing({ kind: 'app', id: rule.subject, label: rule.applicationName ?? rule.subject, placeIds: rule.placeIds, mode: rule.mode })}>
                        <PencilIcon />
                      </Button>
                      <ConfirmAction
                        title="이 앱의 장소 규칙을 삭제할까요?"
                        description="삭제하면 이 앱만의 장소 규칙이 없어지고, 조직 전체 장소 정책만 적용됩니다."
                        details={[{ label: '앱', value: rule.applicationName ?? rule.subject }]}
                        confirmLabel="삭제"
                        onConfirm={() => remove.mutate({ kind: 'app', id: rule.subject, label: '', placeIds: [], mode: 'observe' })}
                      >
                        <Button variant="ghost" size="icon-sm" aria-label={`${rule.applicationName ?? rule.subject} 규칙 삭제`} disabled={remove.isPending}>
                          <Trash2Icon />
                        </Button>
                      </ConfirmAction>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </section>

      <Dialog open={picking !== null} onOpenChange={(open) => !open && setPicking(null)}>
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle>{picking === 'group' ? '규칙을 만들 그룹' : '규칙을 만들 앱'}</DialogTitle>
            <DialogDescription>다음 단계에서 허용할 장소를 고릅니다.</DialogDescription>
          </DialogHeader>
          <Select value={pickedId} onValueChange={setPickedId}>
            <SelectTrigger aria-label={picking === 'group' ? '그룹' : '앱'}>
              <SelectValue placeholder="고르세요" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                {picking === 'group'
                  ? freeGroups.map((group) => <SelectItem key={group.id} value={group.id}>{group.name}</SelectItem>)
                  : freeApps.map((app) => <SelectItem key={app.subject} value={app.subject}>{app.name}</SelectItem>)}
              </SelectGroup>
            </SelectContent>
          </Select>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPicking(null)}>취소</Button>
            <Button disabled={!pickedId} onClick={() => picking && startNew(picking)}>다음</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {editing ? <RuleDialog key={`${editing.kind}-${editing.id}`} target={editing} places={enabledPlaces} onClose={() => setEditing(null)} onSaved={refresh} /> : null}
    </>
  )
}

function RuleDialog({ target, places, onClose, onSaved }: { target: Target; places: Place[]; onClose: () => void; onSaved: () => Promise<unknown> }) {
  const [placeIds, setPlaceIds] = useState(target.placeIds)
  const [mode, setMode] = useState<'observe' | 'enforce'>(target.kind === 'app' ? target.mode : 'enforce')
  const [failure, setFailure] = useState<string | null>(null)

  const save = useMutation({
    mutationFn: () =>
      apiFetch(target.kind === 'group' ? `/api/admin/location/groups/${target.id}` : `/api/admin/location/apps/${encodeURIComponent(target.id)}`, {
        method: 'PUT',
        body: JSON.stringify(target.kind === 'group' ? { placeIds } : { placeIds, mode }),
      }),
    onSuccess: async () => {
      toast.success('규칙을 저장했습니다.')
      await onSaved()
      onClose()
    },
    onError: (error) => setFailure(error instanceof ApiError && /[가-힣]/.test(error.message) ? error.message : '저장하지 못했습니다.'),
  })

  return (
    <Dialog open onOpenChange={(open) => !open && !save.isPending && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{target.label}</DialogTitle>
          <DialogDescription>{target.kind === 'group' ? '이 그룹 사람들이 로그인할 수 있는 장소입니다.' : '이 앱을 열 수 있는 장소입니다.'}</DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            {places.map((place) => (
              <Field key={place.id} orientation="horizontal">
                <Checkbox id={`rule-place-${place.id}`} checked={placeIds.includes(place.id)} onCheckedChange={(on) => setPlaceIds(on === true ? [...placeIds, place.id] : placeIds.filter((id) => id !== place.id))} />
                <FieldLabel htmlFor={`rule-place-${place.id}`}>{place.name}</FieldLabel>
              </Field>
            ))}
          </div>
          {target.kind === 'app' ? (
            <RadioGroup value={mode} onValueChange={(value) => setMode(value as 'observe' | 'enforce')}>
              <Field orientation="horizontal">
                <RadioGroupItem id="rule-mode-observe" value="observe" />
                <FieldLabel htmlFor="rule-mode-observe">기록만 (막지 않음)</FieldLabel>
              </Field>
              <Field orientation="horizontal">
                <RadioGroupItem id="rule-mode-enforce" value="enforce" />
                <FieldLabel htmlFor="rule-mode-enforce">적용 (밖에서는 열 수 없음)</FieldLabel>
              </Field>
            </RadioGroup>
          ) : null}
          {failure ? (
            <Alert variant="destructive">
              <AlertDescription>{failure}</AlertDescription>
            </Alert>
          ) : null}
        </div>
        <DialogFooter>
          <Button variant="outline" disabled={save.isPending} onClick={onClose}>취소</Button>
          <Button disabled={save.isPending || placeIds.length === 0} onClick={() => { setFailure(null); save.mutate() }}>
            {save.isPending ? <Spinner data-icon="inline-start" /> : null}
            저장
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
