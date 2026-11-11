import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ExternalLinkIcon, MapPinIcon, PencilIcon, PlusIcon, Trash2Icon } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '@/components/ui/alert-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Field, FieldContent, FieldDescription, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { Switch } from '@/components/ui/switch'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { ApiError, apiFetch } from '@/lib/api'
import { shareLocation } from '@/lib/location'
import { PlaceDialog } from './places-dialog'
import type { LocationView, Place, Policy, Verdict } from './types'

const MODES: Array<{ value: Policy['mode']; title: string; description: string }> = [
  { value: 'off', title: '끔', description: '위치로 로그인을 제한하지 않습니다.' },
  { value: 'observe', title: '기록만', description: '허용된 장소 밖의 로그인도 막지 않고 감사 로그에만 남깁니다. 적용 전에 영향을 살펴볼 때 쓰세요.' },
  { value: 'enforce', title: '적용', description: '허용된 장소 밖에서는 로그인할 수 없습니다.' },
]

const SIGNALS: Array<{ value: Policy['signal']; title: string; description: string }> = [
  { value: 'network', title: '접속 네트워크의 위치', description: '접속 IP로 서버가 알아낸 위치입니다. 사용자가 바꿀 수 없지만 도시 단위로 거칠고, VPN을 쓰면 VPN 출구 위치로 보입니다.' },
  { value: 'browser', title: '브라우저가 알려 주는 위치', description: '로그인할 때 위치 공유를 요청합니다. 정확하지만 사용자의 기기가 알려 주는 값이라 속일 수 있습니다.' },
  { value: 'network_or_browser', title: '둘 중 하나', description: '네트워크 위치가 허용된 장소면 그대로 통과하고, 아니면 브라우저 위치를 요청합니다.' },
]

function describe(verdict: Verdict): { good: boolean; text: string } {
  const place = verdict.placeName ? `“${verdict.placeName}”` : ''
  switch (verdict.method) {
    case 'off':
      return { good: true, text: '위치 제한이 꺼져 있습니다.' }
    case 'exempt':
      return { good: true, text: '예외 그룹에 속해 있어 위치와 상관없이 통과합니다.' }
    case 'network':
      return { good: true, text: `접속 네트워크 위치가 ${place} 안에 있어 통과합니다.` }
    case 'browser':
      return { good: true, text: `브라우저 위치가 ${place} 안이라 통과합니다.` }
    default:
      if (verdict.reason === 'no_places') return { good: true, text: '켜 둔 장소가 없어 아무도 제한되지 않습니다.' }
      return {
        good: false,
        text:
          verdict.reason === 'outside'
            ? `접속 네트워크 위치가 허용된 장소 밖입니다${verdict.distanceM !== null ? ` (가장 가까운 ${place}에서 ${(verdict.distanceM / 1000).toFixed(1)}km)` : ''}.`
            : verdict.reason === 'no_signal'
              ? '서버가 이 접속의 위치를 알려 주지 않아 확인할 수 없습니다.'
              : '브라우저 위치를 확인해야 합니다.',
      }
  }
}

/** Where people may sign in from: the places, and how a sign-in is checked against them. */
export function LocationsPage() {
  const queryClient = useQueryClient()
  const query = useQuery({ queryKey: ['admin', 'location'], queryFn: () => apiFetch<LocationView>('/api/admin/location') })
  const [editing, setEditing] = useState<Place | 'new' | null>(null)
  const [removing, setRemoving] = useState<Place | null>(null)

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['admin', 'location'] })
  const toggle = useMutation({
    mutationFn: (place: Place) =>
      apiFetch(`/api/admin/location/places/${place.id}`, { method: 'PUT', body: JSON.stringify({ ...place, enabled: !place.enabled }) }),
    onSuccess: refresh,
    onError: () => toast.error('저장하지 못했습니다.'),
  })
  const remove = useMutation({
    mutationFn: (place: Place) => apiFetch(`/api/admin/location/places/${place.id}`, { method: 'DELETE' }),
    onSuccess: async () => {
      toast.success('장소를 지웠습니다.')
      setRemoving(null)
      await refresh()
    },
    onError: () => toast.error('지우지 못했습니다.'),
  })
  const check = useMutation({
    mutationFn: shareLocation,
    onSuccess: async (outcome) => {
      if (outcome === 'ok') toast.success('이 브라우저의 위치가 허용된 장소 안입니다.')
      else toast.error({ outside: '이 브라우저의 위치는 허용된 장소 밖입니다.', inaccurate: '위치가 충분히 정확하지 않습니다.', blocked: '브라우저가 위치 공유를 허용하지 않았습니다.', rate_limited: '시도가 너무 많습니다.', unavailable: '위치를 확인하지 못했습니다. 정책이 브라우저 위치를 쓰도록 켜져 있는지 확인하세요.' }[outcome])
      await refresh()
    },
  })

  if (query.isPending) {
    return (
      <div className="mx-auto flex w-full max-w-5xl flex-col gap-4">
        <Skeleton className="h-8 w-40" />
        <Skeleton className="h-48 w-full" />
        <Skeleton className="h-48 w-full" />
      </div>
    )
  }
  if (query.error) {
    return (
      <div className="mx-auto w-full max-w-5xl">
        <Alert variant="destructive">
          <AlertDescription>위치 설정을 불러오지 못했습니다.</AlertDescription>
        </Alert>
      </div>
    )
  }
  const view = query.data
  const self = describe(view.self)

  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-6">
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-semibold">로그인 위치</h1>
        <p className="text-sm text-muted-foreground">허용할 장소를 만들어 두고, 그 근처에서만 로그인할 수 있게 합니다. 비밀번호·패스키 로그인과 앱 로그인 시작 때 확인합니다.</p>
      </div>

      <section className="flex flex-col gap-3 rounded-2xl border bg-card p-6">
        <h2 className="text-sm font-semibold">지금 내 접속</h2>
        <p className={`flex items-center gap-2 text-sm ${self.good ? '' : 'text-destructive'}`}>
          <MapPinIcon className="size-4 shrink-0" />
          {self.text}
        </p>
        <p className="text-xs text-muted-foreground">
          {view.edge.available
            ? `서버가 파악한 이 접속의 위치: ${[view.edge.city, view.edge.country].filter(Boolean).join(', ') || '알 수 없음'}`
            : '서버가 이 접속의 위치를 알려 주지 않습니다. 개발 환경이거나 위치 정보가 꺼진 경우이며, 이때 네트워크 위치만으로는 확인할 수 없습니다.'}
        </p>
        <div>
          <Button variant="outline" size="sm" disabled={check.isPending || view.policy.mode === 'off'} onClick={() => check.mutate()}>
            {check.isPending ? <Spinner data-icon="inline-start" /> : null}
            이 브라우저의 위치 확인
          </Button>
        </div>
      </section>

      <PolicyCard key={JSON.stringify(view.policy)} view={view} />

      <section className="flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold">허용된 장소</h2>
          <Button size="sm" onClick={() => setEditing('new')}>
            <PlusIcon data-icon="inline-start" />
            장소 추가
          </Button>
        </div>
        {view.places.length === 0 ? (
          <p className="rounded-xl border border-dashed p-8 text-center text-sm text-muted-foreground">장소가 없습니다. 장소를 추가해야 위치 제한을 적용할 수 있습니다.</p>
        ) : (
          <div className="overflow-x-auto rounded-xl border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>이름</TableHead>
                  <TableHead>중심 좌표</TableHead>
                  <TableHead>반경</TableHead>
                  <TableHead>사용</TableHead>
                  <TableHead className="w-24" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {view.places.map((place) => (
                  <TableRow key={place.id}>
                    <TableCell className="font-medium">{place.name}</TableCell>
                    <TableCell>
                      <a className="inline-flex items-center gap-1 text-muted-foreground hover:underline" target="_blank" rel="noopener noreferrer" href={`https://www.openstreetmap.org/?mlat=${place.latitude}&mlon=${place.longitude}#map=15/${place.latitude}/${place.longitude}`}>
                        {place.latitude.toFixed(4)}, {place.longitude.toFixed(4)}
                        <ExternalLinkIcon className="size-3" />
                      </a>
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-muted-foreground">{place.radiusM >= 1000 ? `${(place.radiusM / 1000).toLocaleString('ko-KR')}km` : `${place.radiusM}m`}</TableCell>
                    <TableCell>
                      <Switch aria-label={`${place.name} 사용`} checked={place.enabled} disabled={toggle.isPending} onCheckedChange={() => toggle.mutate(place)} />
                    </TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="icon-sm" aria-label={`${place.name} 수정`} onClick={() => setEditing(place)}>
                        <PencilIcon />
                      </Button>
                      <Button variant="ghost" size="icon-sm" aria-label={`${place.name} 삭제`} onClick={() => setRemoving(place)}>
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

      {editing !== null ? <PlaceDialog key={editing === 'new' ? 'new' : editing.id} open place={editing === 'new' ? null : editing} onClose={() => setEditing(null)} /> : null}
      <AlertDialog open={removing !== null} onOpenChange={(open) => !open && !remove.isPending && setRemoving(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{removing?.name}을(를) 지울까요?</AlertDialogTitle>
            <AlertDialogDescription>이 장소를 근거로 통과한 브라우저 확인도 함께 사라집니다. 남은 장소가 없으면 적용 중인 정책은 아무도 제한하지 않습니다.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={remove.isPending}>취소</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={remove.isPending}
              onClick={(event) => {
                event.preventDefault()
                if (removing) remove.mutate(removing)
              }}
            >
              지우기
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

function PolicyCard({ view }: { view: LocationView }) {
  const queryClient = useQueryClient()
  const [policy, setPolicy] = useState<Policy>(view.policy)
  const [failure, setFailure] = useState<string | null>(null)
  const save = useMutation({
    mutationFn: () => apiFetch('/api/admin/location/policy', { method: 'PUT', body: JSON.stringify(policy) }),
    onSuccess: async () => {
      setFailure(null)
      toast.success('정책을 저장했습니다.')
      await queryClient.invalidateQueries({ queryKey: ['admin', 'location'] })
    },
    onError: (error) => setFailure(error instanceof ApiError && /[가-힣]/.test(error.message) ? error.message : '저장하지 못했습니다.'),
  })
  const usesNetwork = policy.signal !== 'browser'
  const usesBrowser = policy.signal !== 'network'

  return (
    <section className="flex flex-col gap-6 rounded-2xl border bg-card p-6">
      <h2 className="text-sm font-semibold">정책</h2>

      <div className="flex flex-col gap-3">
        <h3 className="text-xs font-medium text-muted-foreground">적용 방식</h3>
        <RadioGroup value={policy.mode} onValueChange={(value) => setPolicy({ ...policy, mode: value as Policy['mode'] })}>
          {MODES.map((entry) => (
            <Field key={entry.value} orientation="horizontal">
              <RadioGroupItem id={`mode-${entry.value}`} value={entry.value} />
              <FieldContent>
                <FieldLabel htmlFor={`mode-${entry.value}`}>{entry.title}</FieldLabel>
                <FieldDescription>{entry.description}</FieldDescription>
              </FieldContent>
            </Field>
          ))}
        </RadioGroup>
      </div>

      <div className="flex flex-col gap-3">
        <h3 className="text-xs font-medium text-muted-foreground">위치를 알아내는 방법</h3>
        <RadioGroup value={policy.signal} onValueChange={(value) => setPolicy({ ...policy, signal: value as Policy['signal'] })}>
          {SIGNALS.map((entry) => (
            <Field key={entry.value} orientation="horizontal">
              <RadioGroupItem id={`signal-${entry.value}`} value={entry.value} />
              <FieldContent>
                <FieldLabel htmlFor={`signal-${entry.value}`}>{entry.title}</FieldLabel>
                <FieldDescription>{entry.description}</FieldDescription>
              </FieldContent>
            </Field>
          ))}
        </RadioGroup>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Field>
          <FieldLabel htmlFor="margin">네트워크 위치 허용 오차 (km)</FieldLabel>
          <Input id="margin" inputMode="numeric" disabled={!usesNetwork} value={policy.networkMarginKm} onChange={(event) => setPolicy({ ...policy, networkMarginKm: Number(event.target.value) || 0 })} />
          <FieldDescription>접속 IP의 위치는 정확하지 않아, 장소 반경에 이만큼을 더해 통과시킵니다.</FieldDescription>
        </Field>
        <Field>
          <FieldLabel htmlFor="accuracy">브라우저 위치 최대 오차 (m)</FieldLabel>
          <Input id="accuracy" inputMode="numeric" disabled={!usesBrowser} value={policy.maxAccuracyM} onChange={(event) => setPolicy({ ...policy, maxAccuracyM: Number(event.target.value) || 0 })} />
          <FieldDescription>이보다 부정확한 브라우저 위치는 받지 않습니다.</FieldDescription>
        </Field>
      </div>

      <div className="flex flex-col gap-3">
        <h3 className="text-xs font-medium text-muted-foreground">예외 그룹</h3>
        <p className="text-xs text-muted-foreground">이 그룹의 사용자는 위치와 상관없이 로그인할 수 있습니다. 출장이나 재택이 많은 사람, 그리고 잠기면 안 되는 관리자 그룹에 쓰세요.</p>
        {view.groups.length === 0 ? (
          <p className="text-sm text-muted-foreground">그룹이 없습니다.</p>
        ) : (
          <div className="grid gap-2 sm:grid-cols-2">
            {view.groups.map((group) => (
              <Field key={group.id} orientation="horizontal">
                <Checkbox
                  id={`exempt-${group.id}`}
                  checked={policy.exemptGroups.includes(group.id)}
                  onCheckedChange={(on) =>
                    setPolicy({ ...policy, exemptGroups: on === true ? [...policy.exemptGroups, group.id] : policy.exemptGroups.filter((id) => id !== group.id) })
                  }
                />
                <FieldLabel htmlFor={`exempt-${group.id}`}>{group.name}</FieldLabel>
              </Field>
            ))}
          </div>
        )}
      </div>

      {policy.mode === 'enforce' ? (
        <Alert>
          <AlertDescription>적용하면 허용된 장소 밖에서는 로그인할 수 없습니다. 지금 이 접속이 허용되지 않으면 저장되지 않으니, 먼저 ‘기록만’으로 영향을 살펴보세요.</AlertDescription>
        </Alert>
      ) : null}
      {failure ? (
        <Alert variant="destructive">
          <AlertDescription>{failure}</AlertDescription>
        </Alert>
      ) : null}
      <div className="flex items-center gap-3">
        <Button disabled={save.isPending} onClick={() => save.mutate()}>
          {save.isPending ? <Spinner data-icon="inline-start" /> : null}
          정책 저장
        </Button>
        {view.policy.mode !== 'off' ? <Badge variant={view.policy.mode === 'enforce' ? 'default' : 'secondary'}>{view.policy.mode === 'enforce' ? '적용 중' : '기록 중'}</Badge> : null}
      </div>
    </section>
  )
}
