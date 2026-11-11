import { useMutation, useQuery } from '@tanstack/react-query'
import { Link, useParams } from '@tanstack/react-router'
import { ArrowLeftIcon, CopyIcon, MailIcon, ScrollTextIcon, TagsIcon } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { apiFetch } from '@/lib/api'
import { formatDateTime } from '@/lib/format'
import { sessionQuery } from '@/lib/queries'
import { AttributesDialog } from './attributes-dialog'
import { UserActions } from './user-actions'
import { ApplicationsTab, GroupsTab } from './user-detail/apps-groups'
import { AuthenticatorsTab, DevicesTab } from './user-detail/devices-auth'
import { ProfileTab } from './user-detail/profile-tab'
import { LogsTab, RolesTab } from './user-detail/roles-logs'
import { useUserData } from './user-detail/shared'

type Detail = {
  user: {
    id: string
    name: string
    email: string
    username: string | null
    roles: string[]
    active: boolean
    lockedDown: boolean
    emailVerified: boolean
    phoneNumber: string | null
    twoFactorEnabled: boolean
    createdAt: string
    lastLoginAt: string | null
    openReports: number
  }
}

const TABS = [
  { value: 'apps', label: '앱' },
  { value: 'groups', label: '그룹' },
  { value: 'profile', label: '프로필' },
  { value: 'devices', label: '기기' },
  { value: 'roles', label: '관리자 역할' },
  { value: 'authenticators', label: '인증 수단' },
  { value: 'logs', label: '로그' },
] as const

type ActivationOutcome = { expiresAt: string; emailed: boolean; activationUrl: string | null; emailError: boolean }

/** One user, in detail: who they are, what they can open, and what has happened to them. */
export function UserDetailPage() {
  const { id } = useParams({ strict: false }) as { id: string }
  const session = useQuery(sessionQuery)
  const detail = useUserData<Detail>(id, 'detail')
  const [tab, setTab] = useState<(typeof TABS)[number]['value']>('apps')
  const [attributes, setAttributes] = useState(false)
  const [link, setLink] = useState<ActivationOutcome | null>(null)

  const sendLink = useMutation({
    mutationFn: async () => (await apiFetch<{ activation: ActivationOutcome }>(`/api/admin/users/${id}/activation-link`, { method: 'POST', body: JSON.stringify({}) })).activation,
    onSuccess: setLink,
    onError: () => toast.error('링크를 만들지 못했습니다.'),
  })

  const back = (
    <div>
      <Button asChild variant="ghost" size="sm">
        <Link to="/admin/users">
          <ArrowLeftIcon data-icon="inline-start" />
          사용자 목록
        </Link>
      </Button>
    </div>
  )

  if (detail.isPending) {
    return (
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-4">
        {back}
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    )
  }
  if (detail.error) {
    return (
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-4">
        {back}
        <Alert variant="destructive">
          <AlertDescription>사용자를 찾을 수 없거나 불러오지 못했습니다.</AlertDescription>
        </Alert>
      </div>
    )
  }

  const user = detail.data.user
  const isAdmin = user.roles.includes('admin')

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      {back}
      <div className="flex flex-wrap items-start justify-between gap-4 rounded-2xl border bg-card p-6">
        <div className="flex min-w-0 items-center gap-4">
          <Avatar size="lg">
            <AvatarFallback>{(user.name || user.email).slice(0, 2).toUpperCase()}</AvatarFallback>
          </Avatar>
          <div className="flex min-w-0 flex-col gap-1">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="truncate text-xl font-semibold">{user.name}</h1>
              {isAdmin ? <Badge>관리자</Badge> : <Badge variant="outline">사용자</Badge>}
              {user.lockedDown ? <Badge variant="destructive">잠김</Badge> : user.active ? <Badge variant="secondary">활성</Badge> : <Badge variant="destructive">비활성</Badge>}
              {user.openReports > 0 ? <Badge variant="destructive">신고 {user.openReports}건</Badge> : null}
            </div>
            <p className="truncate text-sm text-muted-foreground">{user.email}</p>
            <p className="text-xs text-muted-foreground">
              마지막 로그인 {user.lastLoginAt ? formatDateTime(user.lastLoginAt) : '기록 없음'} · 가입 {formatDateTime(user.createdAt)}
              {user.twoFactorEnabled ? ' · 2차 인증 사용' : ''}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => setTab('logs')}>
            <ScrollTextIcon data-icon="inline-start" />
            로그 보기
          </Button>
          <Button variant="outline" size="sm" onClick={() => setAttributes(true)}>
            <TagsIcon data-icon="inline-start" />
            속성
          </Button>
          <Button variant="outline" size="sm" disabled={sendLink.isPending} onClick={() => sendLink.mutate()}>
            <MailIcon data-icon="inline-start" />
            비밀번호 설정 링크
          </Button>
          <UserActions
            user={{ id: user.id, name: user.name, email: user.email, role: user.roles.join(','), banned: !user.active }}
            currentUserId={session.data?.user.id}
            onUnlocked={() => sendLink.mutate()}
          />
        </div>
      </div>

      <Tabs value={tab} onValueChange={(value) => setTab(value as typeof tab)} className="gap-6">
        <TabsList variant="line" className="w-full justify-start overflow-x-auto">
          {TABS.map((entry) => (
            <TabsTrigger key={entry.value} value={entry.value}>
              {entry.label}
            </TabsTrigger>
          ))}
        </TabsList>
        <TabsContent value="apps"><ApplicationsTab id={id} name={user.name} email={user.email} /></TabsContent>
        <TabsContent value="groups"><GroupsTab id={id} /></TabsContent>
        <TabsContent value="profile"><ProfileTab id={id} /></TabsContent>
        <TabsContent value="devices"><DevicesTab id={id} /></TabsContent>
        <TabsContent value="roles"><RolesTab roles={user.roles} /></TabsContent>
        <TabsContent value="authenticators"><AuthenticatorsTab id={id} name={user.name} email={user.email} /></TabsContent>
        <TabsContent value="logs"><LogsTab id={id} /></TabsContent>
      </Tabs>

      <AttributesDialog target={attributes ? { type: 'user', id: user.id, label: user.email } : null} onClose={() => setAttributes(false)} />
      <Dialog open={link !== null} onOpenChange={(open) => !open && setLink(null)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>비밀번호 설정 링크</DialogTitle>
            <DialogDescription>
              {link?.emailed ? `${user.email}으로 링크를 보냈습니다.` : '메일을 보내지 못해 링크를 직접 전달해야 합니다. 이 링크는 지금 한 번만 볼 수 있습니다.'}
            </DialogDescription>
          </DialogHeader>
          {link?.activationUrl ? (
            <div className="flex gap-2">
              <Input readOnly aria-label="비밀번호 설정 링크" value={link.activationUrl} />
              <Button
                variant="outline"
                size="icon"
                aria-label="링크 복사"
                onClick={async () => {
                  await navigator.clipboard.writeText(link.activationUrl!)
                  toast.success('링크를 복사했습니다.')
                }}
              >
                <CopyIcon />
              </Button>
            </div>
          ) : null}
          {link ? <p className="text-sm text-muted-foreground">{formatDateTime(link.expiresAt)}까지 한 번 사용할 수 있습니다.</p> : null}
          <DialogFooter>
            <Button onClick={() => setLink(null)}>확인</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
