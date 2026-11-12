import { ConfirmAction } from '@/components/confirm-dialog'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2Icon, MinusCircleIcon } from 'lucide-react'
import { toast } from 'sonner'
import { useState, type ReactNode } from 'react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { ApiError, apiFetch } from '@/lib/api'
import { formatDateTime } from '@/lib/format'
import { UserMfaDialog } from '../user-mfa-dialog'
import { Failed, Loading, Nothing, Panel, useUserData } from './shared'

type Devices = {
  devices: Array<{ label: string; lastAt: string; location: string | null; ip: string | null; count: number; digests: string[] }>
  sessions: Array<{ id: string; ip: string | null; device: string; createdAt: string; expiresAt: string; current?: boolean }>
  trusted: Array<{ id: string; label: string; createdAt: string; lastSeenAt: string; expiresAt: string; revokedAt: string | null }>
  logins: Array<{ id: string; at: string; ip: string | null; device: string; method: string | null; location: string | null; reported: boolean }>
  reports: Array<{ id: string; loginId: string | null; createdAt: string; status: string }>
  fingerprints: Array<{
    id: string
    at: string
    visitorDigest: string
    networkDigest: string | null
    countryCode: string | null
    latitude: number | null
    longitude: number | null
    geoSource: string | null
    action: string | null
    reasons: string[]
    signals: Record<string, unknown> | null
    level: 'trusted' | 'normal' | 'review' | 'risky' | 'unknown'
    score: number
  }>
}

const TRUST_LABEL: Record<Devices['fingerprints'][number]['level'], string> = {
  trusted: '안전',
  normal: '대체로 안전',
  review: '확인 필요',
  risky: '위험',
  unknown: '평가 없음',
}

const METHODS: Record<string, string> = { password: '비밀번호', passkey: '패스키' }

function Block({ children }: { children: ReactNode }) {
  return <div className="overflow-x-auto rounded-xl border">{children}</div>
}


type Fingerprint = Devices['fingerprints'][number]

const REASON_TEXT: Record<string, string> = {
  incognito_detected: '시크릿 모드 (참고용)',
  developer_tools_detected: '개발자 도구 (참고용)',
  untrusted_device: '등록하지 않은 기기',
  vpn_detected: 'VPN',
  proxy_detected: '프록시',
  privacy_settings_detected: '개인정보 보호 설정',
  rare_device_detected: '드문 기기',
  high_activity_device_detected: '활동이 많은 기기',
  simulator_detected: '시뮬레이터',
  datacenter_ip_detected: '데이터센터 IP',
  low_identification_confidence: '식별 신뢰도 낮음',
  bot_detected: '봇',
  tampering_detected: '변조',
  tor_network_detected: 'Tor',
  ip_blocklisted: '차단 목록 IP',
  virtual_machine_detected: '가상 머신',
  suspect_score_threshold: '의심 점수 초과',
  impossible_travel: '이동 불가능한 위치 변화',
  history_distance_exceeded: '평소 위치에서 멀리 떨어짐',
  geo_position_unavailable: '위치 확인 불가',
  rapid_network_change: '짧은 시간에 네트워크 바뀜',
  rapid_device_change: '짧은 시간에 기기 바뀜',
  rapid_device_and_country_change: '짧은 시간에 기기와 국가가 모두 바뀜',
}

const SIGNAL_LABELS: Array<[string, string]> = [
  ['bot', '봇'], ['tampering', '변조'], ['vpn', 'VPN'], ['proxy', '프록시'], ['incognito', '시크릿 모드'],
  ['developerTools', '개발자 도구'], ['privacySettings', '개인정보 보호 설정'], ['virtualMachine', '가상 머신'],
  ['simulator', '시뮬레이터'], ['rareDevice', '드문 기기'], ['highActivityDevice', '활동 많은 기기'],
  ['torNode', 'Tor'], ['attackSource', '공격 IP 목록'], ['datacenterIp', '데이터센터 IP'],
]

function suspectLabel(score: number): { text: string; tone: 'secondary' | 'outline' | 'destructive' } {
  if (score <= 30) return { text: '낮음', tone: 'secondary' }
  if (score <= 70) return { text: '보통', tone: 'outline' }
  return { text: '높음', tone: 'destructive' }
}

function FingerprintDetail({ entry }: { entry: Fingerprint }) {
  const signals = entry.signals ?? {}
  const suspect = typeof signals.suspectScore === 'number' ? signals.suspectScore : null
  const confidence = typeof signals.confidence === 'number' ? signals.confidence : null
  return (
    <div className="flex flex-col gap-4 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={entry.level === 'risky' ? 'destructive' : 'secondary'}>{TRUST_LABEL[entry.level]}</Badge>
        {entry.level !== 'unknown' ? (
          <span className="text-muted-foreground" title="Fingerprint Pro 의심 점수(Suspect Score)를 뒤집은 값입니다. 100 − 의심 점수.">
            안전 점수 {entry.score}/100
          </span>
        ) : null}
        <span className="text-muted-foreground">판정 {entry.action ?? '기록 없음'}</span>
        {suspect !== null ? (
          <Badge variant={suspectLabel(suspect).tone}>Fingerprint 의심 점수 {suspect} · {suspectLabel(suspect).text}</Badge>
        ) : null}
        {confidence !== null ? <span className="text-muted-foreground">식별 신뢰도 {Math.round(confidence * 100)}%</span> : null}
      </div>
      {entry.reasons.length > 0 ? (
        <div className="flex flex-wrap gap-1.5">
          {entry.reasons.map((reason) => (
            <Badge key={reason} variant="outline">{REASON_TEXT[reason] ?? reason}</Badge>
          ))}
        </div>
      ) : null}
      <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 sm:grid-cols-3">
        {SIGNAL_LABELS.map(([key, label]) => {
          const value = signals[key]
          const on = value === true || (key === 'bot' && value !== undefined && value !== 'not_detected' && value !== null)
          return (
            <div key={key} className="flex items-center justify-between gap-2 border-b py-1">
              <span className="text-muted-foreground">{label}</span>
              <span className={on ? 'font-medium' : 'text-muted-foreground'}>{on ? '감지' : '없음'}</span>
            </div>
          )
        })}
      </div>
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
        <dt className="text-muted-foreground">시각</dt><dd>{formatDateTime(entry.at)}</dd>
        <dt className="text-muted-foreground">국가</dt><dd>{entry.countryCode ?? '-'}</dd>
        <dt className="text-muted-foreground">위치</dt>
        <dd>{entry.latitude === null ? '-' : `${entry.latitude}, ${entry.longitude} (${entry.geoSource ?? '출처 미상'})`}</dd>
        <dt className="text-muted-foreground">기기 해시</dt><dd className="break-all font-mono">{entry.visitorDigest}</dd>
        <dt className="text-muted-foreground">네트워크 해시</dt><dd className="break-all font-mono">{entry.networkDigest ?? '-'}</dd>
      </dl>
      <details>
        <summary className="cursor-pointer text-xs text-muted-foreground">원본 신호 전체</summary>
        <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted p-2 font-mono text-xs">
          {JSON.stringify({ action: entry.action, reasons: entry.reasons, signals: entry.signals }, null, 2)}
        </pre>
      </details>
    </div>
  )
}

function FingerprintDialog({ entry, onClose }: { entry: Fingerprint | null; onClose: () => void }) {
  return (
    <Dialog open={entry !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>기기 지문 상세</DialogTitle>
          <DialogDescription>로그인 순간 기록한 기기 판정과 지문 신호입니다.</DialogDescription>
        </DialogHeader>
        {entry ? <FingerprintDetail entry={entry} /> : null}
      </DialogContent>
    </Dialog>
  )
}

function DeviceFingerprintsDialog({
  device,
  fingerprints,
  onClose,
  onOpen,
}: {
  device: Devices['devices'][number] | null
  fingerprints: Fingerprint[]
  onClose: () => void
  onOpen: (entry: Fingerprint) => void
}) {
  const matching = device ? fingerprints.filter((entry) => device.digests.includes(entry.visitorDigest)) : []
  return (
    <Dialog open={device !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{device?.label ?? '기기'}</DialogTitle>
          <DialogDescription>이 기기로 로그인할 때 기록한 지문 판정입니다.</DialogDescription>
        </DialogHeader>
        {matching.length === 0 ? (
          <Nothing>이 기기에서 기록된 지문이 없습니다. 기기 확인이 켜진 뒤 로그인하면 쌓입니다.</Nothing>
        ) : (
          <div className="flex flex-col gap-2">
            {matching.map((entry) => (
              <button
                key={entry.id}
                type="button"
                className="flex items-center justify-between gap-3 rounded-lg border px-3 py-2 text-left hover:bg-muted/50"
                onClick={() => onOpen(entry)}
              >
                <span className="flex flex-col gap-0.5">
                  <span className="text-sm">{formatDateTime(entry.at)}</span>
                  <span className="text-xs text-muted-foreground">
                    {entry.reasons.length > 0 ? entry.reasons.map((reason) => REASON_TEXT[reason] ?? reason).join(' · ') : '특이 신호 없음'}
                  </span>
                </span>
                <span className="flex items-center gap-2">
                  <Badge variant={entry.level === 'risky' ? 'destructive' : 'secondary'}>{TRUST_LABEL[entry.level]}</Badge>
                  <span className="text-xs text-muted-foreground">{entry.score}/100</span>
                </span>
              </button>
            ))}
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}

export function DevicesTab({ id }: { id: string }) {
  const queryClient = useQueryClient()
  const [openDevice, setOpenDevice] = useState<Devices['devices'][number] | null>(null)
  const [openEntry, setOpenEntry] = useState<Fingerprint | null>(null)
  const query = useUserData<Devices>(id, 'devices')
  const revoke = useMutation({
    mutationFn: (sessionId: string) => apiFetch(`/api/admin/users/${id}/sessions/${sessionId}`, { method: 'DELETE' }),
    onSuccess: async () => {
      toast.success('세션을 종료했습니다.')
      await queryClient.invalidateQueries({ queryKey: ['admin', 'users', 'detail', id] })
    },
    onError: (error) => toast.error(error instanceof ApiError && /[가-힣]/.test(error.message) ? error.message : '세션을 종료하지 못했습니다.'),
  })
  if (query.isPending) return <Loading />
  if (query.error) return <Failed what="기기" />
  const { devices, sessions, trusted, logins, reports, fingerprints } = query.data
  const now = Date.now()
  return (
    <div className="flex flex-col gap-8">
      <Panel title="기기" description="최근 로그인 기록으로 묶은 기기입니다. 기기를 누르면 그 기기의 지문 기록이 열립니다. 로그인 기록은 180일 동안 보관됩니다.">
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
                  <TableRow
                    key={device.label}
                    className="cursor-pointer"
                    tabIndex={0}
                    onClick={() => setOpenDevice(device)}
                    onKeyDown={(event) => event.key === 'Enter' && setOpenDevice(device)}
                  >
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

      <Panel title="기기 지문 기록" description="로그인할 때 기록한 기기 판정과 지문 신호 전체입니다. 기기는 원본 ID가 아니라 키로 만든 해시로만 식별하며, 30일 동안 보관됩니다.">
        {fingerprints.length === 0 ? (
          <Nothing>기록된 기기 지문이 없습니다.</Nothing>
        ) : (
          <Block>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>시각</TableHead>
                  <TableHead>판정</TableHead>
                  <TableHead>기기 해시</TableHead>
                  <TableHead>네트워크 해시</TableHead>
                  <TableHead>국가</TableHead>
                  <TableHead>상세</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {fingerprints.map((entry) => (
                  <TableRow key={entry.id}>
                    <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(entry.at)}</TableCell>
                    <TableCell className="whitespace-nowrap">
                      <Badge variant={entry.level === 'risky' ? 'destructive' : 'secondary'}>{TRUST_LABEL[entry.level]}</Badge>
                      {entry.level !== 'unknown' ? <span className="ml-2 text-muted-foreground">{entry.score}/100</span> : null}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{entry.visitorDigest.slice(0, 12)}</TableCell>
                    <TableCell className="font-mono text-xs">{entry.networkDigest?.slice(0, 12) ?? '-'}</TableCell>
                    <TableCell>{entry.countryCode ?? '-'}</TableCell>
                    <TableCell className="min-w-64 text-xs">
                      <button
                        type="button"
                        className="text-left text-muted-foreground underline-offset-2 hover:underline"
                        onClick={() => setOpenEntry(entry)}
                      >
                        {entry.action ?? '판정 기록 없음'}
                        {entry.reasons.length > 0 ? ` · ${entry.reasons.map((reason) => REASON_TEXT[reason] ?? reason).join(', ')}` : ''}
                      </button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Block>
        )}
      </Panel>

      <DeviceFingerprintsDialog device={openDevice} fingerprints={fingerprints} onClose={() => setOpenDevice(null)} onOpen={setOpenEntry} />
      <FingerprintDialog entry={openEntry} onClose={() => setOpenEntry(null)} />

      <Panel title="열려 있는 세션" description="하나씩 끝낼 수 있습니다. 끝낸 기기는 다시 로그인해야 합니다.">
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
                  <TableHead className="w-28" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions.map((session) => (
                  <TableRow key={session.id}>
                    <TableCell className="font-medium">
                      {session.device}
                      {session.current ? <Badge variant="outline" className="ml-2">지금 쓰는 세션</Badge> : null}
                    </TableCell>
                    <TableCell className="text-muted-foreground">{session.ip ?? '알 수 없음'}</TableCell>
                    <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(session.createdAt)}</TableCell>
                    <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(session.expiresAt)}</TableCell>
                    <TableCell className="text-right">
                      <ConfirmAction
                        title="이 사용자의 세션을 종료할까요?"
                        description="그 기기는 바로 로그아웃됩니다. 이 사용자의 앱 로그인 상태와 토큰은 그대로 남을 수 있으니, 계정이 도용된 것 같다면 모든 세션 종료나 계정 잠금을 쓰세요. 아래 세션이 맞는지 확인하세요."
                        details={[{ label: 'IP', value: session.ip ?? '알 수 없음' }, { label: '시작', value: formatDateTime(session.createdAt) }, { label: '만료', value: formatDateTime(session.expiresAt) }]}
                        confirmLabel="종료"
                        onConfirm={() => revoke.mutate(session.id)}
                      >
                        <Button variant="outline" size="sm" disabled={session.current || revoke.isPending}>
                          종료
                        </Button>
                      </ConfirmAction>
                    </TableCell>
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
