import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState, type FormEvent } from 'react'
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
import { Textarea } from '@/components/ui/textarea'
import { ApiError, apiFetch } from '@/lib/api'
import { TYPE_INFO, type Policy, type PolicyType } from '@/lib/policies'

type Draft = Record<string, string | boolean>

const CREATABLE: PolicyType[] = ['reputation', 'geoip', 'password_expiry', 'password_uniqueness', 'event_matcher', 'password', 'expression']

const EMPTY: Record<PolicyType, Draft> = {
  reputation: { check: 'both', threshold: '-3' },
  geoip: { countries: '', asns: '', maxDistanceKm: '', checkImpossibleTravel: false },
  password_expiry: { days: '180', denyOnly: false },
  password_uniqueness: { count: '5' },
  event_matcher: { action: '', app: '', clientIp: '', query: '' },
  password: { minLength: '12', checkHibp: false, checkStrength: false },
  expression: { expression: '' },
}

function toDraft(policy: Policy): Draft {
  const c = policy.config
  switch (policy.type) {
    case 'reputation':
      return { check: String(c.check ?? 'both'), threshold: String(c.threshold ?? -3) }
    case 'geoip':
      return {
        countries: Array.isArray(c.countries) ? (c.countries as string[]).join(', ') : '',
        asns: Array.isArray(c.asns) ? (c.asns as number[]).join(', ') : '',
        maxDistanceKm: typeof c.maxDistanceKm === 'number' ? String(c.maxDistanceKm) : '',
        checkImpossibleTravel: c.checkImpossibleTravel === true,
      }
    case 'password_expiry':
      return { days: String(c.days ?? 180), denyOnly: c.denyOnly === true }
    case 'password_uniqueness':
      return { count: String(c.count ?? 5) }
    case 'event_matcher':
      return { action: String(c.action ?? ''), app: String(c.app ?? ''), clientIp: String(c.clientIp ?? ''), query: String(c.query ?? '') }
    case 'password':
      return { minLength: String(c.minLength ?? 12), checkHibp: c.checkHibp === true, checkStrength: c.checkStrength === true }
    case 'expression':
      return { expression: String(c.expression ?? '') }
  }
}

function int(value: string, label: string, min: number, max: number): number {
  const n = Number(value)
  if (value.trim() === '' || !Number.isInteger(n) || n < min || n > max) throw new Error(`${label}: ${min}에서 ${max} 사이의 정수를 입력하세요.`)
  return n
}

/** Turn the form into the config the server validates; throws a message to show. */
function toConfig(type: PolicyType, d: Draft, previous: Record<string, unknown>): Record<string, unknown> {
  switch (type) {
    case 'reputation':
      return { check: d.check, threshold: int(String(d.threshold), '기준 점수', -100, 100) }
    case 'geoip': {
      const countries = String(d.countries).split(/[\s,]+/).filter(Boolean)
      if (countries.some((entry) => !/^[A-Za-z]{2}$/.test(entry))) throw new Error('국가는 KR, US처럼 두 글자 코드로 입력하세요.')
      const asns = String(d.asns).split(/[\s,]+/).filter(Boolean).map((entry) => int(entry, 'ASN', 1, 4_294_967_295))
      const maxDistance = String(d.maxDistanceKm).trim()
      const config: Record<string, unknown> = { ...previous, countries: countries.map((c) => c.toUpperCase()), asns, checkImpossibleTravel: d.checkImpossibleTravel === true }
      if (maxDistance) config.maxDistanceKm = int(maxDistance, '최대 거리', 1, 20_000)
      else delete config.maxDistanceKm
      return config
    }
    case 'password_expiry':
      return { days: int(String(d.days), '만료 일수', 1, 3650), denyOnly: d.denyOnly === true }
    case 'password_uniqueness':
      return { ...previous, count: int(String(d.count), '기억할 개수', 1, 32) }
    case 'event_matcher': {
      const config: Record<string, unknown> = {}
      for (const key of ['action', 'app', 'clientIp', 'query'] as const) {
        const value = String(d[key]).trim()
        if (value) config[key] = value
      }
      return config
    }
    case 'password':
      return { ...previous, minLength: int(String(d.minLength), '최소 길이', 8, 128), checkHibp: d.checkHibp === true, checkStrength: d.checkStrength === true }
    case 'expression':
      return { ...previous, expression: String(d.expression) }
  }
}

export function PolicyDialog({ state, onClose }: { state: { policy: Policy | null } | null; onClose: () => void }) {
  const queryClient = useQueryClient()
  const editing = state?.policy ?? null
  const [name, setName] = useState('')
  const [type, setType] = useState<PolicyType>('reputation')
  const [draft, setDraft] = useState<Draft>(EMPTY.reputation)
  const [failure, setFailure] = useState<string | null>(null)

  useEffect(() => {
    if (!state) return
    setFailure(null)
    if (state.policy) {
      setName(state.policy.name)
      setType(state.policy.type)
      setDraft(toDraft(state.policy))
    } else {
      setName('')
      setType('reputation')
      setDraft(EMPTY.reputation)
    }
  }, [state])

  const save = useMutation({
    mutationFn: (config: Record<string, unknown>) =>
      editing
        ? apiFetch(`/api/admin/policies/${editing.id}`, { method: 'PUT', body: JSON.stringify({ config }) })
        : apiFetch('/api/admin/policies', { method: 'POST', body: JSON.stringify({ name: name.trim(), type, config }) }),
    onSuccess: async () => {
      toast.success(editing ? '정책을 저장했습니다.' : '정책을 만들었습니다.')
      onClose()
      await queryClient.invalidateQueries({ queryKey: ['admin', 'policies'] })
    },
    onError: (cause: unknown) => {
      if (cause instanceof ApiError && cause.status === 409) setFailure('같은 이름의 정책이 이미 있습니다.')
      else setFailure(cause instanceof ApiError ? cause.message : '저장하지 못했습니다.')
    },
  })

  function set(key: string, value: string | boolean) {
    setDraft((current) => ({ ...current, [key]: value }))
  }

  function changeType(next: PolicyType) {
    setType(next)
    setDraft(EMPTY[next])
    setFailure(null)
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    let config: Record<string, unknown>
    try {
      config = toConfig(type, draft, editing?.config ?? {})
    } catch (error) {
      setFailure(error instanceof Error ? error.message : '값을 확인하세요.')
      return
    }
    save.mutate(config)
  }

  const text = (key: string, label: string, props: { placeholder?: string; hint?: string; mono?: boolean } = {}) => (
    <Field>
      <FieldLabel htmlFor={`policy-${key}`}>{label}</FieldLabel>
      <Input
        id={`policy-${key}`}
        autoComplete="off"
        spellCheck={false}
        placeholder={props.placeholder}
        className={props.mono ? 'font-mono' : undefined}
        value={String(draft[key] ?? '')}
        onChange={(event) => set(key, event.target.value)}
      />
      {props.hint ? <FieldDescription>{props.hint}</FieldDescription> : null}
    </Field>
  )

  const toggle = (key: string, label: string, description: string) => (
    <Item variant="outline" size="sm">
      <ItemContent>
        <ItemTitle>{label}</ItemTitle>
        <ItemDescription>{description}</ItemDescription>
      </ItemContent>
      <ItemActions>
        <Switch aria-label={label} checked={draft[key] === true} onCheckedChange={(on) => set(key, on)} />
      </ItemActions>
    </Item>
  )

  return (
    <Dialog open={state !== null} onOpenChange={(open) => !open && !save.isPending && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{editing ? `${editing.name} 편집` : '정책 추가'}</DialogTitle>
          <DialogDescription>{TYPE_INFO[type].description}</DialogDescription>
        </DialogHeader>
        <form id="policy-form" onSubmit={submit} noValidate className="max-h-[60vh] overflow-y-auto pr-1">
          <FieldGroup>
            {editing ? null : (
              <>
                <Field>
                  <FieldLabel htmlFor="policy-name">이름</FieldLabel>
                  <Input id="policy-name" autoComplete="off" spellCheck={false} maxLength={64} value={name} onChange={(event) => setName(event.target.value)} />
                  <FieldDescription>영문, 숫자, 점, 밑줄, 하이픈. 예: block-bad-ips</FieldDescription>
                </Field>
                <Field>
                  <FieldLabel htmlFor="policy-type">유형</FieldLabel>
                  <Select value={type} onValueChange={(value) => changeType(value as PolicyType)}>
                    <SelectTrigger id="policy-type" className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        {CREATABLE.map((entry) => (
                          <SelectItem key={entry} value={entry}>
                            {TYPE_INFO[entry].label}
                          </SelectItem>
                        ))}
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                </Field>
              </>
            )}

            {type === 'reputation' ? (
              <>
                <Field>
                  <FieldLabel htmlFor="policy-check">점수를 볼 대상</FieldLabel>
                  <Select value={String(draft.check)} onValueChange={(value) => set('check', value)}>
                    <SelectTrigger id="policy-check" className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        <SelectItem value="ip">IP</SelectItem>
                        <SelectItem value="username">아이디</SelectItem>
                        <SelectItem value="both">IP와 아이디</SelectItem>
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                </Field>
                {text('threshold', '거절할 기준 점수', { hint: '로그인 실패는 -1, 성공은 +1입니다. 이 점수 이하면 거절합니다. -100에서 100.' })}
              </>
            ) : null}

            {type === 'geoip' ? (
              <>
                {text('countries', '허용할 국가', { placeholder: 'KR, JP', hint: '두 글자 코드를 쉼표로 구분합니다.' })}
                {text('asns', '허용할 네트워크(ASN)', { placeholder: '4766, 9318', mono: true, hint: '숫자를 쉼표로 구분합니다.' })}
                {text('maxDistanceKm', '평소 위치에서 허용할 거리 (km)', { hint: '비워 두면 거리를 보지 않습니다.' })}
                {toggle('checkImpossibleTravel', '불가능한 이동 거절', '직전 로그인과의 거리와 시간으로 볼 때 이동할 수 없는 위치면 거절합니다.')}
              </>
            ) : null}

            {type === 'password_expiry' ? (
              <>
                {text('days', '만료 일수', { hint: '1에서 3650일.' })}
                {toggle('denyOnly', '거절만 하기', '켜면 새 비밀번호를 정하게 하지 않고 로그인만 막습니다.')}
              </>
            ) : null}

            {type === 'password_uniqueness' ? text('count', '기억할 비밀번호 개수', { hint: '최근 이만큼의 비밀번호는 다시 쓸 수 없습니다. 1에서 32.' }) : null}

            {type === 'event_matcher' ? (
              <>
                {text('action', '동작', { placeholder: 'authentication.opaque.login', mono: true })}
                {text('app', '앱', { placeholder: 'authentication', mono: true })}
                {text('clientIp', '클라이언트 IP', { mono: true })}
                {text('query', '질의', { hint: '넷 중 하나는 꼭 입력해야 합니다.' })}
              </>
            ) : null}

            {type === 'password' ? (
              <>
                {text('minLength', '최소 길이', { hint: '8에서 128자.' })}
                {toggle('checkHibp', '유출된 비밀번호 검사', '알려진 유출 목록에 있는 비밀번호를 거절합니다.')}
                {toggle('checkStrength', '강도 검사', '추측하기 쉬운 비밀번호를 거절합니다.')}
              </>
            ) : null}

            {type === 'expression' ? (
              <Field>
                <FieldLabel htmlFor="policy-expression">식</FieldLabel>
                <Textarea id="policy-expression" rows={8} spellCheck={false} className="font-mono text-xs" value={String(draft.expression)} onChange={(event) => set('expression', event.target.value)} />
                <FieldDescription>저장할 때 서버가 문법을 검사합니다.</FieldDescription>
              </Field>
            ) : null}

            {failure ? (
              <Field data-invalid>
                <FieldError>{failure}</FieldError>
              </Field>
            ) : null}
          </FieldGroup>
        </form>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose} disabled={save.isPending}>
            취소
          </Button>
          <Button type="submit" form="policy-form" disabled={save.isPending || (!editing && !name.trim())}>
            {save.isPending ? <Spinner data-icon="inline-start" /> : null}
            {editing ? '저장' : '추가'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
