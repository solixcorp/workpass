import { CheckCircle2Icon, MinusCircleIcon } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatDateTime } from '@/lib/format'
import { UserMfaDialog } from '../user-mfa-dialog'
import { Failed, Loading, Nothing, Panel, useUserData } from './shared'

type Devices = {
  devices: Array<{ label: string; lastAt: string; location: string | null; ip: string | null; count: number }>
  sessions: Array<{ id: string; ip: string | null; device: string; createdAt: string; expiresAt: string }>
  trusted: Array<{ id: string; label: string; createdAt: string; lastSeenAt: string; expiresAt: string; revokedAt: string | null }>
  logins: Array<{ id: string; at: string; ip: string | null; device: string; method: string | null; location: string | null; reported: boolean }>
  reports: Array<{ id: string; loginId: string | null; createdAt: string; status: string }>
}

const METHODS: Record<string, string> = { password: '비밀번호', passkey: '패스키' }

function Block({ children }: { children: ReactNode }) {
  return <div className="overflow-x-auto rounded-xl border">{children}</div>
}

export function DevicesTab({ id }: { id: string }) {
  const query = useUserData<Devices>(id, 'devices')
  if (query.isPending) return <Loading />
  if (query.error) return <Failed what="기기" />
  const { devices, sessions, trusted, logins, reports } = query.data
  const now = Date.now()
  return (
    <div className="flex flex-col gap-8">
      <Panel title="기기" description="최근 로그인 기록으로 묶은 기기입니다. 로그인 기록은 180일 동안 보관됩니다.">
        {devices.length === 0 ? (
          <Nothing>로그인 기록이 없습니다.</Nothing>
        ) : (
          <Block>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>기기</TableHead>
                  <TableHead>마지막 로그인</TableHead>
                  <TableHead>위치</TableHead>
                  <TableHead>로그인 횟수</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {devices.map((device) => (
                  <TableRow key={device.label}>
                    <TableCell className="font-medium">{device.label}</TableCell>
                    <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(device.lastAt)}</TableCell>
                    <TableCell className="text-muted-foreground">{device.location ?? device.ip ?? '알 수 없음'}</TableCell>
                    <TableCell>{device.count}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Block>
        )}
      </Panel>

      <Panel title="열려 있는 세션">
        {sessions.length === 0 ? (
          <Nothing>열려 있는 세션이 없습니다.</Nothing>
        ) : (
          <Block>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>기기</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>시작</TableHead>
                  <TableHead>만료</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions.map((session) => (
                  <TableRow key={session.id}>
                    <TableCell className="font-medium">{session.device}</TableCell>
                    <TableCell className="text-muted-foreground">{session.ip ?? '알 수 없음'}</TableCell>
                    <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(session.createdAt)}</TableCell>
                    <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(session.expiresAt)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Block>
        )}
      </Panel>

      <Panel title="신뢰한 기기" description="2차 인증을 건너뛰도록 사용자가 표시해 둔 기기입니다.">
        {trusted.length === 0 ? (
          <Nothing>신뢰한 기기가 없습니다.</Nothing>
        ) : (
          <Block>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>기기</TableHead>
                  <TableHead>마지막 사용</TableHead>
                  <TableHead>만료</TableHead>
                  <TableHead>상태</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {trusted.map((device) => {
                  const active = !device.revokedAt && Date.parse(device.expiresAt) > now
                  return (
                    <TableRow key={device.id}>
                      <TableCell className="font-medium">{device.label}</TableCell>
                      <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(device.lastSeenAt)}</TableCell>
                      <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(device.expiresAt)}</TableCell>
                      <TableCell>{active ? <Badge variant="secondary">사용 중</Badge> : <Badge variant="outline">{device.revokedAt ? '해제됨' : '만료됨'}</Badge>}</TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </Block>
        )}
      </Panel>

      <Panel
        title="로그인 기록"
        description={reports.length ? `사용자가 의심스럽다고 신고한 로그인이 ${reports.length}건 있습니다.` : '최근 100건까지 보입니다.'}
      >
        {logins.length === 0 ? (
          <Nothing>로그인 기록이 없습니다.</Nothing>
        ) : (
          <Block>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>시각</TableHead>
                  <TableHead>기기</TableHead>
                  <TableHead>방식</TableHead>
                  <TableHead>위치</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {logins.map((login) => (
                  <TableRow key={login.id}>
                    <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(login.at)}</TableCell>
                    <TableCell className="font-medium">{login.device}</TableCell>
                    <TableCell>{METHODS[login.method ?? ''] ?? login.method ?? '—'}</TableCell>
                    <TableCell className="text-muted-foreground">{login.location ?? '알 수 없음'}</TableCell>
                    <TableCell className="text-muted-foreground">{login.ip ?? '—'}</TableCell>
                    <TableCell>{login.reported ? <Badge variant="destructive">신고됨</Badge> : null}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Block>
        )}
      </Panel>
    </div>
  )
}

type Authenticators = {
  password: { set: boolean; changedAt: string | null }
  passkeys: Array<{ id: string; name: string | null; createdAt: string; deviceType: string | null }>
  totp: boolean
  otp: boolean
  hardwareTokens: Array<{ id: string; label: string; createdAt: string }>
}

function Row({ title, detail, on }: { title: string; detail: ReactNode; on: boolean }) {
  return (
    <div className="flex items-start gap-3 rounded-xl border bg-card p-4">
      {on ? <CheckCircle2Icon className="mt-0.5 size-4 shrink-0 text-primary" /> : <MinusCircleIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />}
      <div className="flex min-w-0 flex-col gap-0.5">
        <span className="text-sm font-medium">{title}</span>
        <span className="text-xs text-muted-foreground">{detail}</span>
      </div>
    </div>
  )
}

export function AuthenticatorsTab({ id, name, email }: { id: string; name: string; email: string }) {
  const query = useUserData<Authenticators>(id, 'authenticators')
  const [manage, setManage] = useState(false)
  if (query.isPending) return <Loading />
  if (query.error) return <Failed what="인증 수단" />
  const { password, passkeys, totp, otp, hardwareTokens } = query.data
  return (
    <>
      <Panel
        title="등록된 인증 수단"
        description="사용자가 등록해 둔 로그인과 2차 인증 수단입니다."
        action={<Button variant="outline" size="sm" onClick={() => setManage(true)}>2차 인증 관리</Button>}
      >
        <div className="grid gap-3 md:grid-cols-2">
          <Row title="비밀번호" on={password.set} detail={password.set ? (password.changedAt ? `${formatDateTime(password.changedAt)}에 설정` : '설정됨') : '아직 설정하지 않았습니다.'} />
          <Row
            title="패스키"
            on={passkeys.length > 0}
            detail={passkeys.length ? passkeys.map((key) => key.name || '이름 없는 패스키').join(', ') : '등록된 패스키가 없습니다.'}
          />
          <Row title="인증 앱(TOTP)" on={totp} detail={totp ? '등록됨' : '등록하지 않았습니다.'} />
          <Row title="이메일·문자 코드" on={otp} detail={otp ? '사용 중' : '사용하지 않습니다.'} />
          <Row
            title="보안 토큰(HOTP)"
            on={hardwareTokens.length > 0}
            detail={hardwareTokens.length ? hardwareTokens.map((token) => token.label).join(', ') : '연결된 토큰이 없습니다.'}
          />
        </div>
      </Panel>
      <UserMfaDialog user={manage ? { id, name, email } : null} onClose={() => setManage(false)} />
    </>
  )
}
