import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { PencilIcon, PlusIcon, SearchIcon, SlidersHorizontalIcon, Trash2Icon } from 'lucide-react'
import { useMemo, useState } from 'react'
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
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from '@/components/ui/empty'
import { InputGroup, InputGroupAddon, InputGroupInput } from '@/components/ui/input-group'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { ApiError, apiFetch } from '@/lib/api'
import { formatDateTime } from '@/lib/format'
import { PROTOCOL_LABELS } from '@/lib/integrations'
import { AppPolicyDialog, type PolicyApp } from './app-policy-dialog'
import { ApplicationEditDialog } from './application-edit-dialog'
import { NewIntegrationDialog } from './integration/new-integration-dialog'

type AdminApplication = {
  slug: string
  name: string
  description: string
  protocol: 'bookmark' | 'saml' | 'wsfed' | 'oidc' | 'swa'
  binding: string | null
  launchUrl: string | null
  categoryGroup: string | null
  hideFromDashboard?: boolean
  iconKey?: string | null
  iconUrl?: string | null
  enabled: boolean
  protected?: boolean
  createdAt: string
}

type StatusFilter = 'all' | 'active' | 'inactive'

const applicationsKey = ['admin', 'applications'] as const

export function ApplicationsPage() {
  const queryClient = useQueryClient()
  const [createOpen, setCreateOpen] = useState(false)
  const [pendingDelete, setPendingDelete] = useState<AdminApplication | null>(null)
  const [policyApp, setPolicyApp] = useState<PolicyApp | null>(null)
  const [editing, setEditing] = useState<AdminApplication | null>(null)
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState<StatusFilter>('all')

  const { data, isPending, error } = useQuery({
    queryKey: applicationsKey,
    queryFn: async () =>
      (await apiFetch<{ applications: AdminApplication[] }>('/api/admin/applications')).applications,
  })

  const toggle = useMutation({
    mutationFn: ({ slug, enabled }: { slug: string; enabled: boolean }) =>
      apiFetch(`/api/admin/applications/${slug}/${enabled ? 'enable' : 'disable'}`, { method: 'POST' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: applicationsKey }),
    onError: (cause: unknown) =>
      toast.error(cause instanceof ApiError && /[가-힣]/.test(cause.message) ? cause.message : '상태를 바꾸지 못했습니다.'),
  })

  const remove = useMutation({
    mutationFn: (slug: string) => apiFetch(`/api/admin/applications/${slug}`, { method: 'DELETE' }),
    onSuccess: () => {
      toast.success('앱을 삭제했습니다.')
      return queryClient.invalidateQueries({ queryKey: applicationsKey })
    },
    onError: () => toast.error('앱을 삭제하지 못했습니다.'),
  })

  const counts = useMemo(() => {
    const all = data ?? []
    return { all: all.length, active: all.filter((app) => app.enabled).length, inactive: all.filter((app) => !app.enabled).length }
  }, [data])

  const shown = useMemo(() => {
    const term = query.trim().toLowerCase()
    return (data ?? []).filter((app) => {
      if (status === 'active' && !app.enabled) return false
      if (status === 'inactive' && app.enabled) return false
      if (!term) return true
      return [app.name, app.slug, app.binding ?? ''].some((value) => value.toLowerCase().includes(term))
    })
  }, [data, query, status])

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-2xl font-semibold">앱</h1>
        <Button onClick={() => setCreateOpen(true)}>
          <PlusIcon data-icon="inline-start" />앱 연동 만들기
        </Button>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <InputGroup className="max-w-sm">
          <InputGroupAddon>
            <SearchIcon />
          </InputGroupAddon>
          <InputGroupInput
            aria-label="앱 검색"
            placeholder="이름, 식별자, 클라이언트 ID로 검색"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </InputGroup>
        <Tabs value={status} onValueChange={(value) => setStatus(value as StatusFilter)}>
          <TabsList>
            <TabsTrigger value="all">전체 {counts.all}</TabsTrigger>
            <TabsTrigger value="active">활성 {counts.active}</TabsTrigger>
            <TabsTrigger value="inactive">비활성 {counts.inactive}</TabsTrigger>
          </TabsList>
        </Tabs>
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
      ) : shown.length === 0 ? (
        <Empty>
          <EmptyHeader>
            <EmptyTitle>{data.length === 0 ? '등록된 앱이 없습니다' : '조건에 맞는 앱이 없습니다'}</EmptyTitle>
            <EmptyDescription>
              {data.length === 0 ? '앱 연동을 만들면 사용자 포털에 표시됩니다.' : '검색어나 상태를 바꿔 보세요.'}
            </EmptyDescription>
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
                <TableHead className="sticky right-0 bg-background">사용</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {shown.map((application) => (
                <TableRow key={application.slug}>
                  <TableCell>
                    <div className="flex min-w-0 items-center gap-3">
                      <div className="flex size-9 shrink-0 items-center justify-center overflow-hidden rounded-md border bg-card">
                        {application.iconKey || application.iconUrl ? (
                          <img
                            src={application.iconKey ? `/application/${application.slug}/icon` : (application.iconUrl ?? '')}
                            alt=""
                            className="size-full object-contain p-1"
                          />
                        ) : (
                          <span className="text-sm font-medium text-muted-foreground">{application.name.slice(0, 1)}</span>
                        )}
                      </div>
                      <div className="flex min-w-0 flex-col">
                        <Link
                          to="/admin/applications/$slug"
                          params={{ slug: application.slug }}
                          className="truncate font-medium underline-offset-4 hover:underline"
                        >
                          {application.name}
                        </Link>
                        <span className="truncate font-mono text-xs text-muted-foreground">
                          {application.protocol === 'oidc' && application.binding
                            ? `Client ID: ${application.binding}`
                            : application.slug}
                        </span>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{PROTOCOL_LABELS[application.protocol]}</Badge>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{application.categoryGroup ?? '—'}</TableCell>
                  <TableCell className="whitespace-nowrap text-muted-foreground">
                    {formatDateTime(application.createdAt)}
                  </TableCell>
                  <TableCell className="whitespace-nowrap sticky right-0 bg-background">
                    <div className="flex items-center justify-end gap-2">
                      <Switch
                        aria-label={`${application.name} 사용`}
                        checked={application.enabled}
                        disabled={toggle.isPending || application.protected}
                        onCheckedChange={(enabled) => toggle.mutate({ slug: application.slug, enabled })}
                      />
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        aria-label={`${application.name} 편집`}
                        onClick={() => setEditing(application)}
                      >
                        <PencilIcon />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        aria-label={`${application.name} 접근 정책`}
                        onClick={() => setPolicyApp({ slug: application.slug, name: application.name })}
                      >
                        <SlidersHorizontalIcon />
                      </Button>
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
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <NewIntegrationDialog open={createOpen} onOpenChange={setCreateOpen} />
      <AppPolicyDialog app={policyApp} onClose={() => setPolicyApp(null)} />
      <ApplicationEditDialog app={editing} onClose={() => setEditing(null)} />

      <AlertDialog open={pendingDelete !== null} onOpenChange={(open) => !open && setPendingDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{pendingDelete?.name} 앱을 삭제할까요?</AlertDialogTitle>
            <AlertDialogDescription>
              포털에서 사라지고, 이 앱의 로그인 연동(클라이언트, 서비스 제공자 등)도 함께 지워집니다. 되돌릴 수 없습니다.
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
