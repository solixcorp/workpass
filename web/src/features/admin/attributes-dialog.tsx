import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { PlusIcon, Trash2Icon } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { FieldDescription, FieldError } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { ApiError, apiFetch } from '@/lib/api'

export type AttributeTarget = { type: 'user' | 'group' | 'account'; id: string; label: string }

type Kind = 'string' | 'number' | 'boolean' | 'null'
type Row = { key: string; kind: Kind; value: string }
type AttributeValue = string | number | boolean | null

const MAX_ROWS = 32
const KEY_PATTERN = /^[A-Za-z0-9_.:-]{1,64}$/

const KIND_LABELS: Record<Kind, string> = {
  string: '문자',
  number: '숫자',
  boolean: '참/거짓',
  null: '비어 있음',
}

const TYPE_LABELS: Record<AttributeTarget['type'], string> = {
  user: '사용자',
  group: '그룹',
  account: '계정',
}

function toRows(attributes: Record<string, AttributeValue>): Row[] {
  return Object.entries(attributes).map(([key, value]) => {
    if (value === null) return { key, kind: 'null' as const, value: '' }
    if (typeof value === 'boolean') return { key, kind: 'boolean' as const, value: String(value) }
    if (typeof value === 'number') return { key, kind: 'number' as const, value: String(value) }
    return { key, kind: 'string' as const, value }
  })
}

/** Build the API object, or the first problem found, in the order the rows appear. */
function toAttributes(rows: Row[]): { ok: true; attributes: Record<string, AttributeValue> } | { ok: false; error: string } {
  const attributes: Record<string, AttributeValue> = {}
  for (const row of rows) {
    const key = row.key.trim()
    if (!KEY_PATTERN.test(key)) {
      return { ok: false, error: `이름 "${key || '(비어 있음)'}"은 영문, 숫자, 점, 콜론, 밑줄, 하이픈으로 64자까지 쓸 수 있습니다.` }
    }
    if (key in attributes) return { ok: false, error: `이름 "${key}"이 두 번 쓰였습니다.` }
    if (row.kind === 'null') attributes[key] = null
    else if (row.kind === 'boolean') attributes[key] = row.value === 'true'
    else if (row.kind === 'number') {
      const value = Number(row.value)
      if (row.value.trim() === '' || !Number.isFinite(value) || Math.abs(value) > Number.MAX_SAFE_INTEGER) {
        return { ok: false, error: `"${key}"에는 숫자를 입력하세요.` }
      }
      attributes[key] = value
    } else {
      if (row.value.length > 512) return { ok: false, error: `"${key}" 값은 512자까지 입니다.` }
      attributes[key] = row.value
    }
  }
  return { ok: true, attributes }
}

/** Custom attributes of one user, group or account, replaced as a whole on save. */
export function AttributesDialog({ target, onClose }: { target: AttributeTarget | null; onClose: () => void }) {
  const queryClient = useQueryClient()
  const key = ['admin', 'attributes', target?.type, target?.id] as const
  const [rows, setRows] = useState<Row[]>([])
  const [failure, setFailure] = useState<string | null>(null)

  const stored = useQuery({
    queryKey: key,
    enabled: target !== null,
    queryFn: () =>
      apiFetch<{ attributes: Record<string, AttributeValue>; updatedAt: string | null }>(
        `/api/admin/attributes/${target!.type}/${encodeURIComponent(target!.id)}`,
      ),
  })

  useEffect(() => {
    if (stored.data) {
      setRows(toRows(stored.data.attributes))
      setFailure(null)
    }
  }, [stored.data])

  const save = useMutation({
    mutationFn: (attributes: Record<string, AttributeValue>) =>
      apiFetch(`/api/admin/attributes/${target!.type}/${encodeURIComponent(target!.id)}`, {
        method: 'PUT',
        body: JSON.stringify({ attributes }),
      }),
    onSuccess: async () => {
      toast.success('속성을 저장했습니다.')
      await queryClient.invalidateQueries({ queryKey: key })
      onClose()
    },
    onError: (cause: unknown) => setFailure(cause instanceof ApiError ? cause.message : '저장하지 못했습니다.'),
  })

  function update(index: number, patch: Partial<Row>) {
    setRows((current) => current.map((row, i) => (i === index ? { ...row, ...patch } : row)))
  }

  function changeKind(index: number, kind: Kind) {
    update(index, { kind, value: kind === 'boolean' ? 'true' : '' })
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    const built = toAttributes(rows)
    if (!built.ok) {
      setFailure(built.error)
      return
    }
    save.mutate(built.attributes)
  }

  return (
    <Dialog open={target !== null} onOpenChange={(open) => !open && !save.isPending && onClose()}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>
            {target ? TYPE_LABELS[target.type] : ''} 속성 · {target?.label}
          </DialogTitle>
          <DialogDescription>
            앱 로그인 때 토큰 클레임이나 SCIM 동기화로 내보낼 수 있는 값입니다. 저장하면 지금 목록 전체로 바뀝니다.
          </DialogDescription>
        </DialogHeader>

        {stored.error ? (
          <Alert variant="destructive">
            <AlertDescription>속성을 불러오지 못했습니다.</AlertDescription>
          </Alert>
        ) : stored.isPending ? (
          <Skeleton className="h-32 rounded-lg" />
        ) : (
          <form id="attributes" onSubmit={submit} noValidate className="flex max-h-[55vh] flex-col gap-2 overflow-y-auto pr-1">
            {rows.length === 0 ? <p className="text-sm text-muted-foreground">속성이 없습니다.</p> : null}
            {rows.map((row, index) => (
              <div key={index} className="flex items-center gap-2">
                <Input
                  aria-label={`속성 ${index + 1} 이름`}
                  placeholder="이름"
                  autoComplete="off"
                  spellCheck={false}
                  className="w-40 font-mono"
                  value={row.key}
                  onChange={(event) => update(index, { key: event.target.value })}
                />
                <Select value={row.kind} onValueChange={(kind) => changeKind(index, kind as Kind)}>
                  <SelectTrigger className="w-28" aria-label={`속성 ${index + 1} 종류`}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      {(Object.keys(KIND_LABELS) as Kind[]).map((kind) => (
                        <SelectItem key={kind} value={kind}>
                          {KIND_LABELS[kind]}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
                {row.kind === 'boolean' ? (
                  <Select value={row.value} onValueChange={(value) => update(index, { value })}>
                    <SelectTrigger className="flex-1" aria-label={`속성 ${index + 1} 값`}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        <SelectItem value="true">참</SelectItem>
                        <SelectItem value="false">거짓</SelectItem>
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                ) : row.kind === 'null' ? (
                  <span className="flex-1 text-sm text-muted-foreground">값 없음</span>
                ) : (
                  <Input
                    aria-label={`속성 ${index + 1} 값`}
                    placeholder="값"
                    autoComplete="off"
                    className="flex-1"
                    inputMode={row.kind === 'number' ? 'decimal' : undefined}
                    value={row.value}
                    onChange={(event) => update(index, { value: event.target.value })}
                  />
                )}
                <Button
                  type="button"
                  variant="ghost"
                  size="icon-sm"
                  aria-label={`속성 ${index + 1} 삭제`}
                  onClick={() => setRows((current) => current.filter((_, i) => i !== index))}
                >
                  <Trash2Icon />
                </Button>
              </div>
            ))}
            <div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={rows.length >= MAX_ROWS}
                onClick={() => setRows((current) => [...current, { key: '', kind: 'string', value: '' }])}
              >
                <PlusIcon data-icon="inline-start" />속성 추가
              </Button>
            </div>
            <FieldDescription>속성은 {MAX_ROWS}개까지, 전체 크기 4KB까지 저장할 수 있습니다.</FieldDescription>
            {failure ? <FieldError>{failure}</FieldError> : null}
          </form>
        )}

        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose} disabled={save.isPending}>
            취소
          </Button>
          <Button type="submit" form="attributes" disabled={save.isPending || stored.isPending}>
            {save.isPending ? <Spinner data-icon="inline-start" /> : null}
            저장
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
