import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { BellIcon, CheckCheckIcon } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { apiFetch } from '@/lib/api'
import { formatDateTime } from '@/lib/format'
import { notificationsQuery } from '@/lib/me'

/** The bell in the header: unread count, and a panel with the newest notifications. */
export function NotificationBell() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const { data, isPending, error } = useQuery(notificationsQuery)
  const unread = data?.unread ?? 0

  const markRead = useMutation({
    mutationFn: (ids?: string[]) => apiFetch('/api/me/notifications/read', { method: 'POST', body: JSON.stringify(ids ? { ids } : {}) }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: notificationsQuery.queryKey }),
    onError: () => toast.error('읽음으로 표시하지 못했습니다.'),
  })

  return (
    <>
      <Button variant="ghost" size="icon" className="relative" aria-label={unread ? `알림 ${unread}개` : '알림'} onClick={() => setOpen(true)}>
        <BellIcon />
        {unread > 0 ? (
          <span className="absolute -right-0.5 -top-0.5 flex min-w-4 items-center justify-center rounded-full bg-red-700 px-1 text-[10px] font-medium leading-4 text-white">
            {unread > 9 ? '9+' : unread}
          </span>
        ) : null}
      </Button>
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent className="w-full sm:max-w-sm">
          <SheetHeader>
            <SheetTitle>알림</SheetTitle>
            <SheetDescription>{error ? '알림을 불러오지 못했습니다.' : unread ? `읽지 않은 알림 ${unread}개` : '새 알림이 없습니다.'}</SheetDescription>
          </SheetHeader>
          <div className="flex flex-1 flex-col gap-2 overflow-y-auto px-4 pb-4">
            <div>
              <Button variant="link" size="sm" className="px-0" onClick={() => { setOpen(false); void navigate({ to: '/notifications' }) }}>
                모두 보기·알림 설정
              </Button>
            </div>
            {unread > 0 ? (
              <div>
                <Button variant="outline" size="sm" disabled={markRead.isPending} onClick={() => markRead.mutate(undefined)}>
                  <CheckCheckIcon data-icon="inline-start" />
                  모두 읽음
                </Button>
              </div>
            ) : null}
            {error ? (
              <Alert variant="destructive">
                <AlertDescription>알림을 불러오지 못했습니다. 잠시 뒤에 다시 열어 보세요.</AlertDescription>
              </Alert>
            ) : isPending ? (
              <Skeleton className="h-20 w-full" />
            ) : (data?.notifications ?? []).length === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">알림이 없습니다.</p>
            ) : (
              data!.notifications.map((notice) => (
                <button
                  key={notice.id}
                  type="button"
                  className="flex flex-col gap-1 rounded-xl border p-3 text-left transition-colors hover:bg-muted/50"
                  onClick={() => {
                    if (!notice.readAt) markRead.mutate([notice.id])
                    if (notice.link) {
                      setOpen(false)
                      void navigate({ to: notice.link })
                    }
                  }}
                >
                  <span className="flex items-center gap-2 text-sm font-medium">
                    {!notice.readAt ? <span className="size-1.5 shrink-0 rounded-full bg-primary" aria-label="읽지 않음" /> : null}
                    {notice.title}
                  </span>
                  <span className="text-xs text-muted-foreground">{notice.body}</span>
                  <span className="text-xs text-muted-foreground">{formatDateTime(notice.createdAt)}</span>
                </button>
              ))
            )}
          </div>
        </SheetContent>
      </Sheet>
    </>
  )
}
