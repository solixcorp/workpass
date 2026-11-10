import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { ApiError, apiFetch } from '@/lib/api'
import { formatDateTime } from '@/lib/format'

type SettingEntry = {
  key: string
  group: string
  label: string
  description: string
  type: 'enum' | 'int' | 'number' | 'text'
  options?: Array<{ value: string; label: string }>
  min?: number
  max?: number
  step?: number
  maxLength?: number
  unit?: string
  default: string
  value: string
  source: 'admin' | 'env' | 'default'
  updatedAt: string | null
}

type SettingsResponse = {
  groups: Array<{ id: string; label: string; description: string }>
  settings: SettingEntry[]
}

const SOURCE_LABELS: Record<SettingEntry['source'], string> = {
  admin: '관리자 설정',
  env: '배포 설정',
  default: '기본값',
}

const settingsKey = ['admin', 'settings'] as const

type PasswordRulesResponse = {
  title: string
  description: string
  fields: Array<{ name: string; label: string; min: number; max: number; unit: string; value: number }>
  stored: boolean
  effective: Record<string, number>
  otherPolicies: number
}

const rulesKey = ['admin', 'password-rules'] as const

function PasswordRulesCard() {
  const queryClient = useQueryClient()
  const { data, isPending, error } = useQuery({
    queryKey: rulesKey,
    queryFn: () => apiFetch<PasswordRulesResponse>('/api/admin/password-rules'),
  })
  const [draft, setDraft] = useState<Record<string, string>>({})
  const [failure, setFailure] = useState<string | null>(null)

  const save = useMutation({
    mutationFn: (values: Record<string, number>) =>
      apiFetch('/api/admin/password-rules', { method: 'PUT', body: JSON.stringify({ values }) }),
    onSuccess: async () => {
      setFailure(null)
      setDraft({})
      toast.success('비밀번호 규칙을 저장했습니다.')
      await queryClient.invalidateQueries({ queryKey: rulesKey })
    },
    onError: (cause: unknown) =>
      setFailure(cause instanceof ApiError ? cause.message : '저장하지 못했습니다.'),
  })

  if (error) {
    return (
      <Alert variant="destructive">
        <AlertDescription>비밀번호 규칙을 불러오지 못했습니다.</AlertDescription>
      </Alert>
    )
  }
  if (isPending) return <Skeleton className="h-64 rounded-xl" />

  const changed = data.fields.filter(
    (field) => draft[field.name] !== undefined && draft[field.name] !== String(field.value),
  )

  return (
    <Card>
      <CardHeader>
        <CardTitle>{data.title}</CardTitle>
        <CardDescription>{data.description}</CardDescription>
      </CardHeader>
      <CardContent>
        <FieldGroup>
          {failure ? (
            <Alert variant="destructive">
              <AlertDescription>{failure}</AlertDescription>
            </Alert>
          ) : null}
          {data.otherPolicies > 0 ? (
            <Alert>
              <AlertDescription>
                같은 단계에 다른 비밀번호 정책 {data.otherPolicies}개가 연결돼 있습니다. 활성화
                화면에는 그중 가장 엄격한 값이 적용됩니다.
              </AlertDescription>
            </Alert>
          ) : null}
          {data.fields.map((field) => (
            <Field key={field.name}>
              <FieldLabel htmlFor={`rule-${field.name}`}>{field.label}</FieldLabel>
              <div className="flex items-center gap-2">
                <Input
                  id={`rule-${field.name}`}
                  type="number"
                  inputMode="numeric"
                  className="w-28"
                  min={field.min}
                  max={field.max}
                  value={draft[field.name] ?? String(field.value)}
                  disabled={save.isPending}
                  onChange={(event) => setDraft({ ...draft, [field.name]: event.target.value })}
                />
                <span className="text-sm text-muted-foreground">{field.unit}</span>
              </div>
            </Field>
          ))}
          <Field>
            <div>
              <Button
                disabled={changed.length === 0 || save.isPending}
                onClick={() =>
                  save.mutate(Object.fromEntries(changed.map((field) => [field.name, Number(draft[field.name])])))
                }
              >
                {save.isPending ? <Spinner data-icon="inline-start" /> : null}
                저장
              </Button>
            </div>
          </Field>
        </FieldGroup>
      </CardContent>
    </Card>
  )
}

export function SettingsPage() {
  const { data, isPending, error } = useQuery({
    queryKey: settingsKey,
    queryFn: () => apiFetch<SettingsResponse>('/api/admin/settings'),
  })

  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-6">
      <h1 className="text-2xl font-semibold">설정</h1>
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>설정을 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : isPending ? (
        <div className="flex flex-col gap-4">
          {Array.from({ length: 3 }, (_, index) => (
            <Skeleton key={index} className="h-40 rounded-xl" />
          ))}
        </div>
      ) : (
        data.groups.map((group) => {
          const entries = data.settings.filter((entry) => entry.group === group.id)
          if (entries.length === 0) return null
          return (
            <Card key={group.id}>
              <CardHeader>
                <CardTitle>{group.label}</CardTitle>
                <CardDescription>{group.description}</CardDescription>
              </CardHeader>
              <CardContent>
                <FieldGroup>
                  {entries.map((entry) => (
                    <SettingField key={`${entry.key}:${entry.value}:${entry.source}`} entry={entry} />
                  ))}
                </FieldGroup>
              </CardContent>
            </Card>
          )
        })
      )}
      <PasswordRulesCard />
    </div>
  )
}

function SettingField({ entry }: { entry: SettingEntry }) {
  const queryClient = useQueryClient()
  const [draft, setDraft] = useState(entry.value)
  const [error, setError] = useState<string | null>(null)
  const id = `setting-${entry.key}`
  const dirty = draft !== entry.value

  const refresh = () => queryClient.invalidateQueries({ queryKey: settingsKey })
  const failure = (cause: unknown) =>
    setError(cause instanceof ApiError ? cause.message : '저장하지 못했습니다.')

  const save = useMutation({
    mutationFn: (value: string) =>
      apiFetch(`/api/admin/settings/${entry.key}`, { method: 'PUT', body: JSON.stringify({ value }) }),
    onSuccess: async () => {
      setError(null)
      toast.success(`${entry.label}을(를) 저장했습니다.`)
      await refresh()
    },
    onError: failure,
  })

  const reset = useMutation({
    mutationFn: () => apiFetch(`/api/admin/settings/${entry.key}`, { method: 'DELETE' }),
    onSuccess: async () => {
      setError(null)
      toast.success('기본 동작으로 되돌렸습니다.')
      await refresh()
    },
    onError: failure,
  })

  const busy = save.isPending || reset.isPending

  return (
    <Field data-invalid={error ? true : undefined}>
      <div className="flex items-center justify-between gap-2">
        <FieldLabel htmlFor={id}>{entry.label}</FieldLabel>
        <Badge variant={entry.source === 'admin' ? 'secondary' : 'outline'}>
          {SOURCE_LABELS[entry.source]}
        </Badge>
      </div>
      <div className="flex flex-col gap-2 sm:flex-row">
        {entry.type === 'enum' ? (
          <Select value={draft} onValueChange={setDraft} disabled={busy}>
            <SelectTrigger id={id} className="w-full sm:max-w-60">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                {entry.options?.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
        ) : entry.type === 'text' ? (
          <Input
            id={id}
            className="w-full sm:max-w-60"
            maxLength={entry.maxLength}
            aria-invalid={error ? true : undefined}
            value={draft}
            disabled={busy}
            onChange={(event) => setDraft(event.target.value)}
          />
        ) : (
          <div className="flex items-center gap-2">
            <Input
              id={id}
              type="number"
              inputMode="decimal"
              className="w-40"
              min={entry.min}
              max={entry.max}
              step={entry.step ?? 1}
              aria-invalid={error ? true : undefined}
              value={draft}
              disabled={busy}
              onChange={(event) => setDraft(event.target.value)}
            />
            {entry.unit ? <span className="text-sm text-muted-foreground">{entry.unit}</span> : null}
          </div>
        )}
        <div className="flex gap-2">
          <Button disabled={!dirty || busy} onClick={() => save.mutate(draft)}>
            {save.isPending ? <Spinner data-icon="inline-start" /> : null}
            저장
          </Button>
          {entry.source === 'admin' ? (
            <Button variant="outline" disabled={busy} onClick={() => reset.mutate()}>
              되돌리기
            </Button>
          ) : null}
        </div>
      </div>
      <FieldDescription>
        {entry.description}
        {entry.updatedAt ? ` · ${formatDateTime(entry.updatedAt)}에 변경됨` : ''}
      </FieldDescription>
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
    </Field>
  )
}
