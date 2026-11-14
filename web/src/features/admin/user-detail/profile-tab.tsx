import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Spinner } from '@/components/ui/spinner'
import { apiFetch, ApiError } from '@/lib/api'
import { Failed, Loading, Panel, useUserData } from './shared'

type Profile = {
  login: string
  name: string
  email: string
  phoneNumber: string | null
  fields: Record<string, string>
  schema: Array<{ key: string; label: string; group: 'identity' | 'work' | 'contact' | 'locale' }>
}

const GROUPS: Array<{ key: Profile['schema'][number]['group']; title: string }> = [
  { key: 'identity', title: '이름과 호칭' },
  { key: 'work', title: '업무' },
  { key: 'contact', title: '연락처와 주소' },
  { key: 'locale', title: '언어와 시간대' },
]

export function ProfileTab({ id }: { id: string }) {
  const query = useUserData<Profile>(id, 'profile')
  if (query.isPending) return <Loading />
  if (query.error) return <Failed what="프로필" />
  return <ProfileForm key={JSON.stringify(query.data)} id={id} profile={query.data} />
}

function ProfileForm({ id, profile }: { id: string; profile: Profile }) {
  const queryClient = useQueryClient()
  const [name, setName] = useState(profile.name)
  const [phone, setPhone] = useState(profile.phoneNumber ?? '')
  const [fields, setFields] = useState<Record<string, string>>(profile.fields)
  const [failure, setFailure] = useState<string | null>(null)

  const save = useMutation({
    mutationFn: () =>
      apiFetch(`/api/admin/users/${id}/profile`, {
        method: 'PUT',
        body: JSON.stringify({ name: name.trim(), phoneNumber: phone.trim(), fields }),
      }),
    onSuccess: async () => {
      setFailure(null)
      toast.success('프로필을 저장했습니다.')
      await queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
    },
    onError: (error) => setFailure(error instanceof ApiError && /[가-힣]/.test(error.message) ? error.message : '저장하지 못했습니다.'),
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    save.mutate()
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-8">
      <Panel title="기본 정보" description="로그인 이름과 이메일은 여기서 바꿀 수 없습니다.">
        <FieldGroup className="grid gap-4 md:grid-cols-2">
          <Field>
            <FieldLabel htmlFor="profile-login">로그인 이름</FieldLabel>
            <Input id="profile-login" value={profile.login} readOnly />
          </Field>
          <Field>
            <FieldLabel htmlFor="profile-email">이메일</FieldLabel>
            <Input id="profile-email" value={profile.email} readOnly />
          </Field>
          <Field>
            <FieldLabel htmlFor="profile-name">이름</FieldLabel>
            <Input id="profile-name" value={name} maxLength={128} onChange={(event) => setName(event.target.value)} />
          </Field>
          <Field>
            <FieldLabel htmlFor="profile-phone">휴대전화</FieldLabel>
            <Input id="profile-phone" inputMode="tel" placeholder="01012345678" value={phone} onChange={(event) => setPhone(event.target.value)} />
            <FieldDescription>한국 휴대전화 번호(010)만 넣을 수 있습니다. 본인이 확인하기 전에는 인증 코드를 보내는 데 쓰이지 않습니다.</FieldDescription>
          </Field>
        </FieldGroup>
      </Panel>
      {GROUPS.map((group) => (
        <Panel key={group.key} title={group.title}>
          <FieldGroup className="grid gap-4 md:grid-cols-2">
            {profile.schema
              .filter((field) => field.group === group.key)
              .map((field) => (
                <Field key={field.key}>
                  <FieldLabel htmlFor={`profile-${field.key}`}>{field.label}</FieldLabel>
                  <Input
                    id={`profile-${field.key}`}
                    maxLength={256}
                    value={fields[field.key] ?? ''}
                    onChange={(event) => setFields({ ...fields, [field.key]: event.target.value })}
                  />
                </Field>
              ))}
          </FieldGroup>
        </Panel>
      ))}
      {failure ? (
        <Alert variant="destructive">
          <AlertDescription>{failure}</AlertDescription>
        </Alert>
      ) : null}
      <div>
        <Button type="submit" disabled={save.isPending}>
          {save.isPending ? <Spinner data-icon="inline-start" /> : null}
          저장
        </Button>
      </div>
    </form>
  )
}
