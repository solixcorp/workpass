import { useQuery } from '@tanstack/react-query'
import { UserRoundIcon, XIcon } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { apiFetch } from '@/lib/api'

export type PickedPerson = { id: string; name: string; email: string }

/** Find a person by name or e-mail and pick them. */
export function PersonPicker({ value, onChange, placeholder = '사용자 찾기' }: { value: PickedPerson | null; onChange: (person: PickedPerson | null) => void; placeholder?: string }) {
  const [text, setText] = useState('')
  const [debounced, setDebounced] = useState('')
  const [open, setOpen] = useState(false)

  useEffect(() => {
    const timer = setTimeout(() => setDebounced(text.trim()), 250)
    return () => clearTimeout(timer)
  }, [text])

  const results = useQuery({
    queryKey: ['admin', 'person-search', debounced],
    enabled: open && debounced.length >= 1,
    queryFn: async () => {
      const params = new URLSearchParams({ limit: '8', searchField: debounced.includes('@') ? 'email' : 'name', searchOperator: 'contains', searchValue: debounced })
      const found = await apiFetch<{ users: Array<{ id: string; name: string; email: string }> }>(`/api/auth/admin/list-users?${params}`)
      return found.users
    },
  })

  if (value) {
    return (
      <div className="flex h-9 items-center gap-2 rounded-lg border bg-muted/40 pl-3 pr-1 text-sm">
        <UserRoundIcon className="size-4 text-muted-foreground" />
        <span className="max-w-40 truncate font-medium">{value.name}</span>
        <Button variant="ghost" size="icon-sm" aria-label="사용자 선택 해제" onClick={() => onChange(null)}>
          <XIcon />
        </Button>
      </div>
    )
  }
  return (
    <div className="relative">
      <Input
        aria-label={placeholder}
        className="w-52"
        placeholder={placeholder}
        value={text}
        autoComplete="off"
        onChange={(event) => {
          setText(event.target.value)
          setOpen(true)
        }}
        onFocus={() => setOpen(true)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        onKeyDown={(event) => event.key === 'Escape' && setOpen(false)}
      />
      {open && debounced ? (
        <ul className="absolute left-0 top-10 z-20 w-72 overflow-hidden rounded-xl border bg-popover p-1 shadow-md">
          {results.isPending ? (
            <li className="px-3 py-2 text-sm text-muted-foreground">찾는 중…</li>
          ) : (results.data ?? []).length === 0 ? (
            <li className="px-3 py-2 text-sm text-muted-foreground">일치하는 사용자가 없습니다.</li>
          ) : (
            results.data!.map((person) => (
              <li key={person.id}>
                <button
                  type="button"
                  className="flex w-full flex-col rounded-lg px-3 py-2 text-left hover:bg-muted"
                  onMouseDown={(event) => {
                    event.preventDefault()
                    onChange(person)
                    setText('')
                    setOpen(false)
                  }}
                >
                  <span className="text-sm font-medium">{person.name}</span>
                  <span className="text-xs text-muted-foreground">{person.email}</span>
                </button>
              </li>
            ))
          )}
        </ul>
      ) : null}
    </div>
  )
}
