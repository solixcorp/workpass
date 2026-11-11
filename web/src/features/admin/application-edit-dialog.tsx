import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ImageIcon, Trash2Icon, UploadIcon } from 'lucide-react'
import { useRef, useState, type ChangeEvent, type FormEvent } from 'react'
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
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Item, ItemActions, ItemContent, ItemDescription, ItemMedia, ItemTitle } from '@/components/ui/item'
import { Spinner } from '@/components/ui/spinner'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { ApiError, apiFetch } from '@/lib/api'

export type EditableApplication = {
  slug: string
  name: string
  description: string
  protocol: string
  launchUrl: string | null
  categoryGroup: string | null
  hideFromDashboard?: boolean
  iconKey?: string | null
  iconUrl?: string | null
  protected?: boolean
}

const ICON_MAX_BYTES = 1024 * 1024
const ICON_TYPES = ['image/png', 'image/jpeg', 'image/webp', 'image/gif', 'image/svg+xml']

function iconSource(app: EditableApplication, version: number): string | null {
  if (app.iconKey) return `/application/${app.slug}/icon?v=${version}`
  return app.iconUrl ?? null
}

export function ApplicationEditDialog({
  app,
  onClose,
}: {
  app: EditableApplication | null
  onClose: () => void
}) {
  return (
    <Dialog open={app !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-lg">
        {app ? <EditForm key={app.slug} app={app} onClose={onClose} /> : null}
      </DialogContent>
    </Dialog>
  )
}

function EditForm({ app, onClose }: { app: EditableApplication; onClose: () => void }) {
  const queryClient = useQueryClient()
  const fileInput = useRef<HTMLInputElement>(null)
  const [name, setName] = useState(app.name)
  const [description, setDescription] = useState(app.description)
  const [categoryGroup, setCategoryGroup] = useState(app.categoryGroup ?? '')
  const [launchUrl, setLaunchUrl] = useState(app.launchUrl ?? '')
  const [hidden, setHidden] = useState(app.hideFromDashboard === true)
  const [hasUploadedIcon, setHasUploadedIcon] = useState(Boolean(app.iconKey))
  const [iconVersion, setIconVersion] = useState(() => Date.now())
  const [failure, setFailure] = useState<string | null>(null)
  const [iconFailure, setIconFailure] = useState<string | null>(null)
  const locked = app.protected === true

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['admin', 'applications'] })

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiFetch(`/api/admin/applications/${app.slug}`, { method: 'PATCH', body: JSON.stringify(body) }),
    onSuccess: async () => {
      toast.success('앱 정보를 저장했습니다.')
      await refresh()
      onClose()
    },
    onError: (cause: unknown) => setFailure(cause instanceof ApiError ? cause.message : '저장하지 못했습니다.'),
  })

  const upload = useMutation({
    mutationFn: async (file: File) => {
      const form = new FormData()
      form.set('file', file)
      const response = await fetch(`/api/admin/applications/${app.slug}/icon`, {
        method: 'POST',
        body: form,
        credentials: 'same-origin',
      })
      if (!response.ok) {
        const text = await response.text()
        let message = '아이콘을 올리지 못했습니다.'
        try {
          const parsed = JSON.parse(text) as { error?: string }
          if (response.status === 400 && parsed.error?.startsWith('The icon must be')) {
            message = '아이콘 파일을 확인하세요. PNG, JPEG, WebP, GIF, SVG만 되고 1MB 이하여야 합니다.'
          } else if (response.status === 400 && !parsed.error) {
            message = '아이콘을 올리지 못했습니다.'
          }
        } catch {
          /* keep the generic message */
        }
        throw new Error(message)
      }
    },
    onSuccess: async () => {
      setHasUploadedIcon(true)
      setIconVersion(Date.now())
      setIconFailure(null)
      toast.success('아이콘을 올렸습니다.')
      await refresh()
    },
    onError: (cause: Error) => setIconFailure(cause.message),
  })

  const removeIcon = useMutation({
    mutationFn: () => apiFetch(`/api/admin/applications/${app.slug}/icon`, { method: 'DELETE' }),
    onSuccess: async () => {
      setHasUploadedIcon(false)
      setIconFailure(null)
      toast.success('아이콘을 지웠습니다.')
      await refresh()
    },
    onError: () => setIconFailure('아이콘을 지우지 못했습니다.'),
  })

  function pickFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    if (!ICON_TYPES.includes(file.type) && !/\.(png|jpe?g|webp|gif|svg)$/i.test(file.name)) {
      setIconFailure('PNG, JPEG, WebP, GIF, SVG 파일만 올릴 수 있습니다.')
      return
    }
    if (file.size > ICON_MAX_BYTES) {
      setIconFailure('아이콘은 1MB 이하여야 합니다.')
      return
    }
    setIconFailure(null)
    upload.mutate(file)
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    const trimmedName = name.trim()
    if (!locked && (trimmedName.length === 0 || trimmedName.length > 128)) {
      setFailure('이름은 1자에서 128자 사이여야 합니다.')
      return
    }
    if (description.length > 512) {
      setFailure('설명은 512자를 넘을 수 없습니다.')
      return
    }
    if (categoryGroup.trim().length > 64) {
      setFailure('그룹은 64자를 넘을 수 없습니다.')
      return
    }
    const url = launchUrl.trim()
    if (!locked && url) {
      let parsed: URL | null = null
      try {
        parsed = new URL(url)
      } catch {
        parsed = null
      }
      if (!parsed || parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash) {
        setFailure('실행 주소는 https로 시작해야 하고 계정 정보나 #이 들어가면 안 됩니다.')
        return
      }
    }
    const body: Record<string, unknown> = {
      description,
      categoryGroup: categoryGroup.trim() || null,
    }
    if (!locked) {
      body.name = trimmedName
      body.launchUrl = url || null
      body.hideFromDashboard = hidden
    }
    save.mutate(body)
  }

  const source = hasUploadedIcon ? `/application/${app.slug}/icon?v=${iconVersion}` : iconSource({ ...app, iconKey: null }, iconVersion)
  const busy = save.isPending || upload.isPending || removeIcon.isPending

  return (
    <>
      <DialogHeader>
        <DialogTitle>{app.name} 편집</DialogTitle>
        <DialogDescription>
          식별자 <code className="font-mono">{app.slug}</code>와 방식은 바꿀 수 없습니다.
        </DialogDescription>
      </DialogHeader>
      <form id="application-edit" onSubmit={submit} noValidate>
        <FieldGroup>
          {failure ? (
            <Alert variant="destructive">
              <AlertDescription>{failure}</AlertDescription>
            </Alert>
          ) : null}
          <Field>
            <FieldLabel htmlFor="edit-app-name">이름</FieldLabel>
            <Input id="edit-app-name" value={name} maxLength={128} disabled={locked} onChange={(event) => setName(event.target.value)} />
            {locked ? <FieldDescription>기본 앱의 이름과 주소는 바꿀 수 없습니다.</FieldDescription> : null}
          </Field>
          <Field>
            <FieldLabel htmlFor="edit-app-description">설명</FieldLabel>
            <Textarea id="edit-app-description" rows={2} maxLength={512} value={description} onChange={(event) => setDescription(event.target.value)} />
            <FieldDescription>포털 앱 카드에 보입니다.</FieldDescription>
          </Field>
          <Field>
            <FieldLabel htmlFor="edit-app-group">그룹</FieldLabel>
            <Input id="edit-app-group" maxLength={64} value={categoryGroup} onChange={(event) => setCategoryGroup(event.target.value)} />
          </Field>
          <Field>
            <FieldLabel htmlFor="edit-app-url">{app.protocol === 'oidc' && !locked ? '로그인 시작 주소' : '실행 주소'}</FieldLabel>
            <Input
              id="edit-app-url"
              type="url"
              autoComplete="off"
              spellCheck={false}
              placeholder="https://"
              disabled={locked}
              value={launchUrl}
              onChange={(event) => setLaunchUrl(event.target.value)}
            />
            {app.protocol === 'oidc' && !locked ? (
              <FieldDescription>
                포털에서 이 앱을 누르면 이 주소로 이동하며 발급자(iss) 값이 붙습니다. 앱이 이 주소에서 로그인 요청을 시작해야 바로 들어갈 수 있습니다. 비워 두면 타일이 눌리지 않습니다.
              </FieldDescription>
            ) : null}
          </Field>
          <Item variant="outline" size="sm">
            <ItemMedia variant={source ? 'image' : 'icon'}>
              {source ? <img src={source} alt="" /> : <ImageIcon />}
            </ItemMedia>
            <ItemContent>
              <ItemTitle>아이콘</ItemTitle>
              <ItemDescription>
                {iconFailure ?? 'PNG, JPEG, WebP, GIF, SVG, 1MB 이하'}
              </ItemDescription>
            </ItemContent>
            <ItemActions>
              <input ref={fileInput} type="file" hidden accept={ICON_TYPES.join(',')} onChange={pickFile} aria-label="아이콘 파일" />
              <Button type="button" variant="outline" size="sm" disabled={busy} onClick={() => fileInput.current?.click()}>
                {upload.isPending ? <Spinner data-icon="inline-start" /> : <UploadIcon data-icon="inline-start" />}
                올리기
              </Button>
              {hasUploadedIcon ? (
                <Button type="button" variant="ghost" size="icon-sm" aria-label="아이콘 지우기" disabled={busy} onClick={() => removeIcon.mutate()}>
                  <Trash2Icon />
                </Button>
              ) : null}
            </ItemActions>
          </Item>
          <Item variant="outline" size="sm">
            <ItemContent>
              <ItemTitle>포털에서 숨기기</ItemTitle>
              <ItemDescription>켜 두면 사용자 포털 목록에 나오지 않습니다. 접근 권한은 그대로입니다.</ItemDescription>
            </ItemContent>
            <ItemActions>
              <Switch aria-label="포털에서 숨기기" checked={hidden} disabled={locked} onCheckedChange={setHidden} />
            </ItemActions>
          </Item>
        </FieldGroup>
      </form>
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onClose} disabled={save.isPending}>
          취소
        </Button>
        <Button type="submit" form="application-edit" disabled={busy}>
          {save.isPending ? <Spinner data-icon="inline-start" /> : null}
          저장
        </Button>
      </DialogFooter>
    </>
  )
}
