import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { PlusIcon, XIcon } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { apiFetch } from '@/lib/api'
import { formatDateTime } from '@/lib/format'
import { groupsQuery } from '@/lib/integrations'
import { UserAppsDialog } from '../user-apps-dialog'
import { Failed, Loading, Nothing, Panel, useUserData } from './shared'

type UserApp = {
  slug: string
  name: string
  protocol: string
  enabled: boolean
  hidden: boolean
  icon: string | null
  access: 'everyone' | 'group' | 'none'
  via: string[]
  lastSignInAt: string | null
}

const PROTOCOLS: Record<string, string> = { bookmark: '북마크', saml: 'SAML', wsfed: 'WS-Fed', oidc: 'OIDC', swa: 'SWA' }

export function ApplicationsTab({ id, name, email }: { id: string; name: string; email: string }) {
  const query = useUserData<{ applications: UserApp[] }>(id, 'applications')
  const [activity, setActivity] = useState(false)
  if (query.isPending) return <Loading />
  if (query.error) return <Failed what="앱 목록" />
  const mine = query.data.applications.filter((app) => app.access !== 'none')
  return (
    <Panel
      title="할당된 앱"
      description="앱은 그룹 단위로만 할당됩니다. 이 사용자에게 앱을 주거나 빼려면 그룹을 바꾸거나 앱의 할당 설정을 바꾸세요."
      action={
        <Button variant="outline" size="sm" onClick={() => setActivity(true)}>
          허용한 권한·위험 기록
        </Button>
      }
    >
      {mine.length === 0 ? (
        <Nothing>이 사용자가 열 수 있는 앱이 없습니다.</Nothing>
      ) : (
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>앱</TableHead>
                <TableHead>방식</TableHead>
                <TableHead>할당 경로</TableHead>
                <TableHead>상태</TableHead>
                <TableHead>마지막 로그인</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {mine.map((app) => (
                <TableRow key={app.slug}>
                  <TableCell>
                    <Link to="/admin/applications/$slug" params={{ slug: app.slug }} className="flex min-w-0 max-w-56 items-center gap-3 font-medium hover:underline">
                      {app.icon ? (
                        <img src={app.icon} alt="" className="size-6 rounded-md border object-contain" />
                      ) : (
                        <span className="flex size-6 items-center justify-center rounded-md bg-muted text-xs">{app.name.slice(0, 1)}</span>
                      )}
                      <span className="truncate">{app.name}</span>
                    </Link>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{PROTOCOLS[app.protocol] ?? app.protocol}</TableCell>
                  <TableCell>
                    {app.access === 'everyone' ? (
                      <Badge variant="outline">전체 조직</Badge>
                    ) : (
                      <div className="flex flex-wrap gap-1">
                        {app.via.map((name) => (
                          <Badge key={name} variant="secondary">그룹: {name}</Badge>
                        ))}
                      </div>
                    )}
                  </TableCell>
                  <TableCell>{app.enabled ? <Badge variant="secondary">켜짐</Badge> : <Badge variant="outline">꺼짐</Badge>}</TableCell>
                  <TableCell className="whitespace-nowrap text-muted-foreground">{app.lastSignInAt ? formatDateTime(app.lastSignInAt) : '기록 없음'}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      <UserAppsDialog user={activity ? { id, name, email } : null} onClose={() => setActivity(false)} />
    </Panel>
  )
}

export function GroupsTab({ id }: { id: string }) {
  const queryClient = useQueryClient()
  const query = useUserData<{ groups: Array<{ id: string; name: string; description: string | null }> }>(id, 'groups')
  const all = useQuery(groupsQuery)
  const [picked, setPicked] = useState('')

  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ['admin', 'users', 'detail', id] })
    await queryClient.invalidateQueries({ queryKey: ['admin', 'groups'] })
  }
  const add = useMutation({
    mutationFn: (groupId: string) =>
      apiFetch(`/api/admin/directory-groups/${groupId}/members`, { method: 'POST', body: JSON.stringify({ userId: id }) }),
    onSuccess: async () => {
      setPicked('')
      toast.success('그룹에 추가했습니다.')
      await refresh()
    },
    onError: () => toast.error('그룹에 추가하지 못했습니다.'),
  })
  const remove = useMutation({
    mutationFn: (groupId: string) => apiFetch(`/api/admin/directory-groups/${groupId}/members/${id}`, { method: 'DELETE' }),
    onSuccess: async () => {
      toast.success('그룹에서 뺐습니다.')
      await refresh()
    },
    onError: () => toast.error('그룹에서 빼지 못했습니다.'),
  })

  if (query.isPending) return <Loading />
  if (query.error) return <Failed what="그룹" />
  const joined = new Set(query.data.groups.map((group) => group.id))
  const choices = (all.data ?? []).filter((group) => !joined.has(group.id))

  return (
    <Panel
      title="그룹"
      description="그룹에 들어가면 그 그룹에 할당된 앱을 열 수 있게 됩니다."
      action={
        <div className="flex items-center gap-2">
          <Select value={picked} onValueChange={setPicked}>
            <SelectTrigger aria-label="추가할 그룹" className="w-48">
              <SelectValue placeholder={choices.length ? '그룹 고르기' : '추가할 그룹 없음'} />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                {choices.map((group) => (
                  <SelectItem key={group.id} value={group.id}>{group.name}</SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
          <Button size="sm" disabled={!picked || add.isPending} onClick={() => add.mutate(picked)}>
            <PlusIcon data-icon="inline-start" />
            추가
          </Button>
        </div>
      }
    >
      {query.data.groups.length === 0 ? (
        <Nothing>어느 그룹에도 속하지 않았습니다.</Nothing>
      ) : (
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>그룹</TableHead>
                <TableHead>설명</TableHead>
                <TableHead className="w-12" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {query.data.groups.map((group) => (
                <TableRow key={group.id}>
                  <TableCell className="font-medium">{group.name}</TableCell>
                  <TableCell className="text-muted-foreground">{group.description || '—'}</TableCell>
                  <TableCell>
                    <Button variant="ghost" size="icon-sm" aria-label={`${group.name}에서 빼기`} disabled={remove.isPending} onClick={() => remove.mutate(group.id)}>
                      <XIcon />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </Panel>
  )
}
