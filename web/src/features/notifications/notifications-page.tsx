import { ConfirmAction } from '@/components/confirm-dialog'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { CheckCheckIcon, Trash2Icon } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Field, FieldContent, FieldDescription, FieldLabel } from '@/components/ui/field'
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { Paginator } from '@/components/paginator'
import { apiFetch } from '@/lib/api'
import { formatDateTime } from '@/lib/format'
import { notificationPreferencesQuery, type NotificationCategory, type NotificationPage, type PagedNotification } from '@/lib/me'

const CATEGORY_LABELS: Record<NotificationCategory, string> = { security: '보안', apps: '앱', requests: '접근 요청' }

/** Every notification, with filters and pages, and which kinds a person wants to receive. */
export function NotificationsPage() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [category, setCategory] = useState('all')
  const [unreadOnly, setUnreadOnly] = useState(false)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)

  const query = useQuery({
    queryKey: ['me', 'notifications', 'page', category, unreadOnly, page, pageSize],
    queryFn: () => {
      const params = new URLSearchParams({ page: String(page), limit: String(pageSize) })
      if (category !== 'all') params.set('category', category)
      if (unreadOnly) params.set('unread', '1')
      return apiFetch<NotificationPage>(`/api/me/notifications?${params}`)
    },
    placeholderData: keepPreviousData,
  })
  const preferences = useQuery(notificationPreferencesQuery)

  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ['me', 'notifications'] })
  }
  const markRead = useMutation({
    mutationFn: (ids?: string[]) => apiFetch('/api/me/notifications/read', { method: 'POST', body: JSON.stringify(ids ? { ids } : {}) }),
    onSuccess: refresh,
    onError: () => toast.error('읽음으로 표시하지 못했습니다.'),
  })
  const remove = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/me/notifications/${id}`, { method: 'DELETE' }),
    onSuccess: refresh,
    onError: () => toast.error('지우지 못했습니다.'),
  })
  const clearRead = useMutation({
    mutationFn: () => apiFetch<{ deleted: number }>('/api/me/notifications?read=1', { method: 'DELETE' }),
    onSuccess: async (result) => {
      toast.success(`읽은 알림 ${result.deleted}개를 지웠습니다.`)
      setPage(1)
      await refresh()
    },
    onError: () => toast.error('지우지 못했습니다.'),
  })
  const savePreference = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      apiFetch('/api/me/notification-preferences', { method: 'PUT', body: JSON.stringify({ categories: { [id]: enabled } }) }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: notificationPreferencesQuery.queryKey }),
    onError: () => toast.error('저장하지 못했습니다.'),
  })

  const items = query.data?.notifications ?? []
  const unread = query.data?.unread ?? 0

  function open(notice: PagedNotification) {
    if (!notice.readAt) markRead.mutate([notice.id])
    if (notice.link) void navigate({ to: notice.link })
  }

  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-6">
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-semibold">알림</h1>
        <p className="text-sm text-muted-foreground">{unread ? `읽지 않은 알림 ${unread}개` : '읽지 않은 알림이 없습니다.'}</p>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Select value={category} onValueChange={(value) => { setCategory(value); setPage(1) }}>
          <SelectTrigger aria-label="종류" className="w-36">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              <SelectItem value="all">모든 종류</SelectItem>
              {(Object.keys(CATEGORY_LABELS) as NotificationCategory[]).map((key) => (
                <SelectItem key={key} value={key}>
                  {CATEGORY_LABELS[key]}
                </SelectItem>
              ))}
            </SelectGroup>
          </SelectContent>
        </Select>
        <Button variant={unreadOnly ? 'secondary' : 'outline'} size="sm" aria-pressed={unreadOnly} onClick={() => { setUnreadOnly(!unreadOnly); setPage(1) }}>
          읽지 않은 것만
        </Button>
        <div className="ml-auto flex items-center gap-2">
          <Button variant="outline" size="sm" disabled={unread === 0 || markRead.isPending} onClick={() => markRead.mutate(undefined)}>
            <CheckCheckIcon data-icon="inline-start" />
            모두 읽음
          </Button>
          <Button variant="outline" size="sm" disabled={clearRead.isPending} onClick={() => clearRead.mutate()}>
            <Trash2Icon data-icon="inline-start" />
            읽은 알림 지우기
          </Button>
        </div>
      </div>

      {query.error ? (
        <Alert variant="destructive">
          <AlertDescription>알림을 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : query.isPending ? (
        <Skeleton className="h-48 w-full" />
      ) : items.length === 0 ? (
        <p className="rounded-xl border border-dashed p-10 text-center text-sm text-muted-foreground">알림이 없습니다.</p>
      ) : (
        <>
          <ul className={`flex flex-col gap-2 transition-opacity ${query.isPlaceholderData ? 'opacity-60' : ''}`}>
            {items.map((notice) => (
              <li key={notice.id} className="flex items-start gap-2 rounded-xl border bg-card p-4">
                <button type="button" className="flex min-w-0 flex-1 flex-col gap-1 text-left" onClick={() => open(notice)}>
                  <span className="flex flex-wrap items-center gap-2 text-sm font-medium">
                    {!notice.readAt ? <span className="size-1.5 shrink-0 rounded-full bg-primary" aria-label="읽지 않음" /> : null}
                    {notice.title}
                    <Badge variant="outline">{CATEGORY_LABELS[notice.category] ?? notice.category}</Badge>
                  </span>
                  <span className="text-xs text-muted-foreground">{notice.body}</span>
                  <span className="text-xs text-muted-foreground">{formatDateTime(notice.createdAt)}</span>
                </button>
                <ConfirmAction
                  title="이 알림을 지울까요?"
                  description="지운 알림은 다시 볼 수 없습니다."
                  details={[{ label: '알림', value: notice.title }, { label: '시각', value: formatDateTime(notice.createdAt) }]}
                  confirmLabel="지우기"
                  onConfirm={() => remove.mutate(notice.id)}
                >
                  <Button variant="ghost" size="icon-sm" aria-label="알림 지우기" disabled={remove.isPending}>
                    <Trash2Icon />
                  </Button>
                </ConfirmAction>
              </li>
            ))}
          </ul>
          <Paginator page={page} pageSize={pageSize} total={query.data?.total ?? 0} onPage={setPage} onPageSize={(size) => { setPageSize(size); setPage(1) }} sizes={[10, 25, 50]} />
        </>
      )}

      <section className="flex flex-col gap-4 rounded-2xl border bg-card p-6">
        <div className="flex flex-col gap-1">
          <h2 className="text-sm font-semibold">받을 알림</h2>
          <p className="text-xs text-muted-foreground">끄면 그 종류의 새 알림이 생기지 않습니다. 보안 알림은 계정을 지키기 위해 끌 수 없습니다.</p>
        </div>
        {preferences.isPending ? (
          <Skeleton className="h-24 w-full" />
        ) : preferences.error ? (
          <Alert variant="destructive">
            <AlertDescription>설정을 불러오지 못했습니다.</AlertDescription>
          </Alert>
        ) : (
          preferences.data.categories.map((entry) => (
            <Field key={entry.id} orientation="horizontal">
              <FieldContent>
                <FieldLabel htmlFor={`pref-${entry.id}`}>{entry.label}</FieldLabel>
                <FieldDescription>{entry.description}</FieldDescription>
              </FieldContent>
              <Switch id={`pref-${entry.id}`} checked={entry.enabled} disabled={entry.locked || savePreference.isPending} onCheckedChange={(enabled) => savePreference.mutate({ id: entry.id, enabled })} />
            </Field>
          ))
        )}
      </section>
    </div>
  )
}

