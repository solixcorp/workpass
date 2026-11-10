import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { PlusIcon, Trash2Icon } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
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
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from '@/components/ui/empty'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@/components/ui/field'
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
import { Switch } from '@/components/ui/switch'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { apiFetch } from '@/lib/api'
import { formatDateTime } from '@/lib/format'

type AdminApplication = {
  slug: string
  name: string
  description: string
  protocol: 'bookmark' | 'saml' | 'wsfed' | 'oidc' | 'swa'
  binding: string | null
  launchUrl: string | null
  categoryGroup: string | null
  enabled: boolean
  protected?: boolean
  createdAt: string
}

const PROTOCOL_LABELS: Record<AdminApplication['protocol'], string> = {
  bookmark: '북마크',
  oidc: 'OIDC',
  saml: 'SAML',
  wsfed: 'WS-Fed',
  swa: 'SWA',
}

const applicationsKey = ['admin', 'applications'] as const

export function ApplicationsPage() {
  const queryClient = useQueryClient()
  const [createOpen, setCreateOpen] = useState(false)
  const [pendingDelete, setPendingDelete] = useState<AdminApplication | null>(null)

  const { data, isPending, error } = useQuery({
    queryKey: applicationsKey,
    queryFn: async () =>
      (await apiFetch<{ applications: AdminApplication[] }>('/api/admin/applications')).applications,
  })

  const toggle = useMutation({
    mutationFn: ({ slug, enabled }: { slug: string; enabled: boolean }) =>
      apiFetch(`/api/admin/applications/${slug}/${enabled ? 'enable' : 'disable'}`, { method: 'POST' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: applicationsKey }),
    onError: () => toast.error('상태를 바꾸지 못했습니다.'),
  })

  const remove = useMutation({
    mutationFn: (slug: string) => apiFetch(`/api/admin/applications/${slug}`, { method: 'DELETE' }),
    onSuccess: () => {
      toast.success('앱을 삭제했습니다.')
      return queryClient.invalidateQueries({ queryKey: applicationsKey })
    },
    onError: () => toast.error('앱을 삭제하지 못했습니다.'),
  })

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-2xl font-semibold">앱</h1>
        <Button onClick={() => setCreateOpen(true)}>
          <PlusIcon data-icon="inline-start" />앱 추가
        </Button>
      </div>

      {error ? (
        <Alert variant="destructive">
          <AlertDescription>앱 목록을 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : isPending ? (
        <div className="flex flex-col gap-2">
          {Array.from({ length: 4 }, (_, index) => (
            <Skeleton key={index} className="h-12 rounded-md" />
          ))}
        </div>
      ) : data.length === 0 ? (
        <Empty>
          <EmptyHeader>
            <EmptyTitle>등록된 앱이 없습니다</EmptyTitle>
            <EmptyDescription>앱을 추가하면 사용자 포털에 표시됩니다.</EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>앱</TableHead>
                <TableHead>방식</TableHead>
                <TableHead>그룹</TableHead>
                <TableHead>등록일</TableHead>
                <TableHead>사용</TableHead>
                <TableHead className="w-12" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.map((application) => (
                <TableRow key={application.slug}>
                  <TableCell>
                    <div className="flex min-w-0 flex-col">
                      <span className="truncate font-medium">{application.name}</span>
                      <span className="truncate font-mono text-xs text-muted-foreground">
                        {application.slug}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{PROTOCOL_LABELS[application.protocol]}</Badge>
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {application.categoryGroup ?? '—'}
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-muted-foreground">
                    {formatDateTime(application.createdAt)}
                  </TableCell>
                  <TableCell>
                    <Switch
                      aria-label={`${application.name} 사용`}
                      checked={application.enabled}
                      disabled={toggle.isPending || application.protected}
                      onCheckedChange={(enabled) => toggle.mutate({ slug: application.slug, enabled })}
                    />
                  </TableCell>
                  <TableCell>
                    {application.protected ? (
                      <Badge variant="secondary">기본 앱</Badge>
                    ) : (
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        aria-label={`${application.name} 삭제`}
                        onClick={() => setPendingDelete(application)}
                      >
                        <Trash2Icon />
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <CreateApplicationDialog open={createOpen} onOpenChange={setCreateOpen} />

      <AlertDialog open={pendingDelete !== null} onOpenChange={(open) => !open && setPendingDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{pendingDelete?.name} 앱을 삭제할까요?</AlertDialogTitle>
            <AlertDialogDescription>
              포털에서 사라지고 되돌릴 수 없습니다. 연결된 로그인 설정은 그대로 남습니다.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>취소</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (pendingDelete) remove.mutate(pendingDelete.slug)
                setPendingDelete(null)
              }}
            >
              삭제
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

function CreateApplicationDialog({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const queryClient = useQueryClient()
  const [slug, setSlug] = useState('')
  const [name, setName] = useState('')
  const [protocol, setProtocol] = useState<AdminApplication['protocol']>('bookmark')
  const [launchUrl, setLaunchUrl] = useState('')
  const [categoryGroup, setCategoryGroup] = useState('')
  const [error, setError] = useState<string | null>(null)

  const create = useMutation({
    mutationFn: () =>
      apiFetch('/api/admin/applications', {
        method: 'POST',
        body: JSON.stringify({
          slug,
          name,
          protocol,
          launchUrl: launchUrl.trim() || null,
          categoryGroup: categoryGroup.trim() || null,
        }),
      }),
    onSuccess: async () => {
      toast.success('앱을 추가했습니다. 사용하려면 켜 주세요.')
      await queryClient.invalidateQueries({ queryKey: applicationsKey })
      setSlug('')
      setName('')
      setLaunchUrl('')
      setCategoryGroup('')
      setError(null)
      onOpenChange(false)
    },
    onError: (failure: Error) => setError(failure.message),
  })

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(null)
    create.mutate()
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={handleSubmit} noValidate className="flex flex-col gap-6">
          <DialogHeader>
            <DialogTitle>앱 추가</DialogTitle>
            <DialogDescription>새 앱은 꺼진 상태로 만들어집니다.</DialogDescription>
          </DialogHeader>
          <FieldGroup>
            {error ? (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            ) : null}
            <Field>
              <FieldLabel htmlFor="app-name">이름</FieldLabel>
              <Input id="app-name" required value={name} onChange={(event) => setName(event.target.value)} />
            </Field>
            <Field>
              <FieldLabel htmlFor="app-slug">식별자</FieldLabel>
              <Input
                id="app-slug"
                required
                autoCapitalize="off"
                placeholder="slack"
                value={slug}
                onChange={(event) => setSlug(event.target.value)}
              />
              <FieldDescription>영문 소문자, 숫자, 하이픈만 쓸 수 있습니다.</FieldDescription>
            </Field>
            <Field>
              <FieldLabel htmlFor="app-protocol">방식</FieldLabel>
              <Select
                value={protocol}
                onValueChange={(value) => setProtocol(value as AdminApplication['protocol'])}
              >
                <SelectTrigger id="app-protocol" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    {(Object.keys(PROTOCOL_LABELS) as Array<AdminApplication['protocol']>).map((key) => (
                      <SelectItem key={key} value={key}>
                        {PROTOCOL_LABELS[key]}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </Field>
            <Field>
              <FieldLabel htmlFor="app-url">실행 주소</FieldLabel>
              <Input
                id="app-url"
                type="url"
                placeholder="https://"
                value={launchUrl}
                onChange={(event) => setLaunchUrl(event.target.value)}
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="app-group">그룹</FieldLabel>
              <Input
                id="app-group"
                placeholder="업무 도구"
                value={categoryGroup}
                onChange={(event) => setCategoryGroup(event.target.value)}
              />
            </Field>
          </FieldGroup>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              취소
            </Button>
            <Button type="submit" disabled={create.isPending || !slug || !name}>
              {create.isPending ? <Spinner data-icon="inline-start" /> : null}
              추가
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
