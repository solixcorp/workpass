import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { ApiError, apiFetch } from '@/lib/api'
import { assignmentKey, assignmentQuery, groupsQuery } from '@/lib/integrations'
import { AssignmentChooser, Section, SettingRow, type AssignChoice } from './parts'

/** Who may open the app. Saved as one change, for the dashboard card and the sign-in gate together. */
export function AssignmentPanel({ slug }: { slug: string }) {
  const queryClient = useQueryClient()
  const stored = useQuery(assignmentQuery(slug))
  const groups = useQuery(groupsQuery)
  const [choice, setChoice] = useState<AssignChoice>('everyone')
  const [selected, setSelected] = useState<string[]>([])
  const [failure, setFailure] = useState<string | null>(null)

  useEffect(() => {
    if (!stored.data) return
    setChoice(stored.data.mode)
    setSelected(stored.data.groups.map((group) => group.id))
  }, [stored.data])

  const save = useMutation({
    mutationFn: () =>
      apiFetch(`/api/admin/applications/${slug}/assignment`, {
        method: 'PUT',
        body: JSON.stringify(choice === 'groups' ? { mode: 'groups', groups: selected } : { mode: 'everyone' }),
      }),
    onSuccess: async () => {
      setFailure(null)
      toast.success('할당을 저장했습니다.')
      await queryClient.invalidateQueries({ queryKey: assignmentKey(slug) })
    },
    onError: (cause: unknown) => setFailure(cause instanceof ApiError && /[가-힣]/.test(cause.message) ? cause.message : '저장하지 못했습니다.'),
  })

  if (stored.error) {
    return (
      <Alert variant="destructive">
        <AlertDescription>할당 정보를 불러오지 못했습니다.</AlertDescription>
      </Alert>
    )
  }
  if (stored.isPending) return <Skeleton className="h-48 rounded-2xl" />

  const dirty =
    choice !== stored.data.mode ||
    (choice === 'groups' &&
      [...selected].sort().join() !== stored.data.groups.map((group) => group.id).sort().join())

  return (
    <div className="flex flex-col gap-4">
      <Section title="할당">
        <SettingRow
          title="접근 허용 대상"
          description="이 앱을 포털에서 보고 로그인할 수 있는 사람입니다. 개별 사용자가 아니라 그룹 단위로 정합니다."
        >
          <AssignmentChooser
            choice={choice}
            onChoice={setChoice}
            groups={groups.data}
            loading={groups.isPending}
            selected={selected}
            onSelected={setSelected}
            allowLater={false}
          />
        </SettingRow>
      </Section>
      {failure ? (
        <Alert variant="destructive">
          <AlertDescription>{failure}</AlertDescription>
        </Alert>
      ) : null}
      <div>
        <Button disabled={!dirty || save.isPending || (choice === 'groups' && selected.length === 0)} onClick={() => save.mutate()}>
          {save.isPending ? <Spinner data-icon="inline-start" /> : null}
          저장
        </Button>
      </div>
    </div>
  )
}
