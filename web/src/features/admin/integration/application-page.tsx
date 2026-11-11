import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate, useParams } from '@tanstack/react-router'
import { ArrowLeftIcon, PencilIcon, ShieldCheckIcon, Trash2Icon } from 'lucide-react'
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
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ApiError, apiFetch } from '@/lib/api'
import { deleteMessage, type DeleteResult } from '@/lib/application-delete'
import { PROTOCOL_LABELS } from '@/lib/integrations'
import { AppPolicyDialog } from '../app-policy-dialog'
import { ApplicationEditDialog, type EditableApplication } from '../application-edit-dialog'
import { AssignmentPanel } from './assignment-panel'
import { EntitlementsPanel } from './entitlements-panel'
import { ProvisioningPanel } from './provisioning-panel'
import { SignOnPanel } from './sign-on-panel'

type AdminApplication = EditableApplication & {
  enabled: boolean
  description: string
  categoryGroup: string | null
}

/** One app: its state, its sign-in connection, and who may open it. */

export function ApplicationPage() {
  const { slug } = useParams({ strict: false }) as { slug: string }
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [editing, setEditing] = useState<EditableApplication | null>(null)
  const [policyOpen, setPolicyOpen] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)

  const key = ['admin', 'application', slug] as const
  const { data, isPending, error } = useQuery({
    queryKey: key,
    queryFn: async () => (await apiFetch<{ application: AdminApplication }>(`/api/admin/applications/${slug}`)).application,
  })

  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: key })
    await queryClient.invalidateQueries({ queryKey: ['admin', 'applications'] })
  }

  const toggle = useMutation({
    mutationFn: (enabled: boolean) => apiFetch(`/api/admin/applications/${slug}/${enabled ? 'enable' : 'disable'}`, { method: 'POST' }),
    onSuccess: refresh,
    onError: (cause: unknown) =>
      toast.error(cause instanceof ApiError && /[가-힣]/.test(cause.message) ? cause.message : '상태를 바꾸지 못했습니다.'),
  })

  const remove = useMutation({
    mutationFn: () => apiFetch<DeleteResult>(`/api/admin/applications/${slug}`, { method: 'DELETE' }),
    onSuccess: async (result) => {
      toast.success(deleteMessage(result))
      await queryClient.invalidateQueries({ queryKey: ['admin', 'applications'] })
      void navigate({ to: '/admin/applications' })
    },
    onError: (cause: unknown) => {
      setConfirmDelete(false)
      toast.error(cause instanceof ApiError && /[가-힣]/.test(cause.message) ? cause.message : '앱을 삭제하지 못했습니다.')
    },
  })

  if (error) {
    return (
      <div className="mx-auto flex w-full max-w-4xl flex-col gap-4">
        <Alert variant="destructive">
          <AlertDescription>앱을 불러오지 못했습니다.</AlertDescription>
        </Alert>
        <div>
          <Button asChild variant="outline">
            <Link to="/admin/applications">앱 목록으로</Link>
          </Button>
        </div>
      </div>
    )
  }
  if (isPending) {
    return (
      <div className="mx-auto flex w-full max-w-4xl flex-col gap-4">
        <Skeleton className="h-24 rounded-2xl" />
        <Skeleton className="h-64 rounded-2xl" />
      </div>
    )
  }

  const app = data
  const icon = app.iconKey ? `/application/${app.slug}/icon` : app.iconUrl
  const protectedApp = app.protected === true

  return (
    <div className="mx-auto flex w-full max-w-4xl flex-col gap-6">
      <Button asChild variant="ghost" size="sm" className="self-start">
        <Link to="/admin/applications">
          <ArrowLeftIcon data-icon="inline-start" />앱 목록
        </Link>
      </Button>

      <header className="flex flex-wrap items-center gap-4">
        <div className="flex size-16 shrink-0 items-center justify-center overflow-hidden rounded-2xl border bg-card">
          {icon ? <img src={icon} alt="" className="size-full object-contain p-2" /> : <span className="text-xl font-semibold text-muted-foreground">{app.name.slice(0, 1)}</span>}
        </div>
        <div className="flex min-w-0 flex-1 flex-col gap-1">
          <h1 className="truncate text-xl font-semibold">{app.name}</h1>
          <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
            <Badge variant={app.enabled ? 'secondary' : 'outline'}>{app.enabled ? '활성' : '비활성'}</Badge>
            <Badge variant="outline">{PROTOCOL_LABELS[app.protocol] ?? app.protocol}</Badge>
            <span className="font-mono text-xs">{app.slug}</span>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Switch
            aria-label={`${app.name} 사용`}
            checked={app.enabled}
            disabled={toggle.isPending || protectedApp}
            onCheckedChange={(enabled) => toggle.mutate(enabled)}
          />
          <Button variant="outline" size="sm" onClick={() => setEditing(app)}>
            <PencilIcon data-icon="inline-start" />
            정보 편집
          </Button>
          <Button variant="outline" size="sm" onClick={() => setPolicyOpen(true)}>
            <ShieldCheckIcon data-icon="inline-start" />
            접근 정책
          </Button>
          {protectedApp ? (
            <Badge variant="secondary">기본 앱</Badge>
          ) : (
            <Button variant="ghost" size="icon-sm" aria-label={`${app.name} 삭제`} onClick={() => setConfirmDelete(true)}>
              <Trash2Icon />
            </Button>
          )}
        </div>
      </header>

      <Tabs defaultValue="sign-on" className="gap-6">
        <TabsList variant="line">
          <TabsTrigger value="sign-on">로그인 방식</TabsTrigger>
          <TabsTrigger value="assignments">할당</TabsTrigger>
          {['oidc', 'saml', 'wsfed'].includes(app.protocol) ? <TabsTrigger value="entitlements">권한</TabsTrigger> : null}
          <TabsTrigger value="provisioning">프로비저닝</TabsTrigger>
        </TabsList>
        <TabsContent value="sign-on">
          <SignOnPanel slug={app.slug} name={app.name} protocol={app.protocol} />
        </TabsContent>
        <TabsContent value="assignments">
          <AssignmentPanel slug={app.slug} />
        </TabsContent>
        <TabsContent value="entitlements">
          <EntitlementsPanel slug={app.slug} />
        </TabsContent>
        <TabsContent value="provisioning">
          <ProvisioningPanel slug={app.slug} />
        </TabsContent>
      </Tabs>

      <ApplicationEditDialog app={editing} onClose={() => { setEditing(null); void refresh() }} />
      <AppPolicyDialog app={policyOpen ? { slug: app.slug, name: app.name } : null} onClose={() => setPolicyOpen(false)} />

      <AlertDialog open={confirmDelete} onOpenChange={(open) => !remove.isPending && setConfirmDelete(open)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{app.name}을(를) 삭제할까요?</AlertDialogTitle>
            <AlertDialogDescription>
              앱과 이 앱의 로그인 연동(클라이언트, 서비스 제공자 등)이 함께 지워지고 되돌릴 수 없습니다. 이 앱으로 로그인하던 사용자는 더 이상 열 수 없습니다.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={remove.isPending}>취소</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={remove.isPending}
              onClick={(event) => {
                event.preventDefault()
                remove.mutate()
              }}
            >
              {remove.isPending ? <Spinner data-icon="inline-start" /> : null}
              삭제
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
