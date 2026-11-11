import { useQuery } from '@tanstack/react-query'
import { CircleHelpIcon, SearchIcon, XIcon } from 'lucide-react'
import { useMemo, useState, type FormEvent } from 'react'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { apiFetch } from '@/lib/api'
import type { QueryHelp } from './types'

/** The word being typed at the cursor end, for suggesting field names. */
function lastWord(text: string): string {
  const match = text.match(/([A-Za-z_.]+)$/)
  return match ? match[1]! : ''
}

/**
 * A search box that takes a small SQL-like language (`outcome = "failure" and ip startswith "203."`).
 * It suggests field names while typing and has a help page built from what the server says it understands.
 */
export function QueryBar({ applied, error, onApply }: { applied: string; error: { message: string; position: number | null } | null; onApply: (query: string) => void }) {
  const [draft, setDraft] = useState(applied)
  const [helpOpen, setHelpOpen] = useState(false)
  const [focused, setFocused] = useState(false)
  const help = useQuery({ queryKey: ['admin', 'audit-fields'], queryFn: () => apiFetch<QueryHelp>('/api/admin/audit-events/fields'), staleTime: 3_600_000, retry: false })

  const names = useMemo(() => (help.data?.fields ?? []).flatMap((field) => [field.name, ...field.aliases]), [help.data])
  const word = lastWord(draft)
  const suggestions = word && focused ? names.filter((name) => name.startsWith(word.toLowerCase()) && name !== word.toLowerCase()).slice(0, 6) : []

  function submit(event: FormEvent) {
    event.preventDefault()
    onApply(draft.trim())
  }
  function complete(name: string) {
    setDraft(draft.slice(0, draft.length - word.length) + name + ' ')
  }

  return (
    <div className="flex flex-col gap-1.5">
      <form onSubmit={submit} className="relative flex items-center gap-2">
        <div className="relative flex-1">
          <Input
            aria-label="검색 조건"
            aria-invalid={error ? true : undefined}
            className="font-mono text-sm"
            placeholder={'검색: outcome = "failure" and ip startswith "203.0.113."'}
            autoComplete="off"
            spellCheck={false}
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            onFocus={() => setFocused(true)}
            onBlur={() => setTimeout(() => setFocused(false), 120)}
          />
          {suggestions.length ? (
            <ul className="absolute left-0 top-10 z-20 w-60 overflow-hidden rounded-xl border bg-popover p-1 shadow-md">
              {suggestions.map((name) => (
                <li key={name}>
                  <button type="button" className="w-full rounded-lg px-3 py-1.5 text-left font-mono text-sm hover:bg-muted" onMouseDown={(event) => { event.preventDefault(); complete(name) }}>
                    {name}
                  </button>
                </li>
              ))}
            </ul>
          ) : null}
        </div>
        <Button type="submit" variant="outline" size="icon" aria-label="검색">
          <SearchIcon />
        </Button>
        {applied ? (
          <Button type="button" variant="ghost" size="icon" aria-label="검색 조건 지우기" onClick={() => { setDraft(''); onApply('') }}>
            <XIcon />
          </Button>
        ) : null}
        <Button type="button" variant="ghost" size="icon" aria-label="검색 문법 도움말" onClick={() => setHelpOpen(true)}>
          <CircleHelpIcon />
        </Button>
      </form>
      {error ? (
        <p className="text-xs text-destructive" role="alert">
          {error.message}
          {error.position !== null ? ` (${error.position + 1}번째 글자 근처)` : ''}
        </p>
      ) : null}

      <Dialog open={helpOpen} onOpenChange={setHelpOpen}>
        <DialogContent className="max-h-[85svh] overflow-y-auto sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>검색 문법</DialogTitle>
            <DialogDescription>
              <code>필드 연산자 값</code> 꼴의 조건을 <code>and</code>, <code>or</code>, 괄호로 묶습니다. 값은 따옴표로 감쌉니다. 글자가 들어 있는지는 <code>~</code>, 들어 있지 않은지는 <code>!~</code>, 같지 않음은 <code>!=</code>, 목록에 없음은 <code>not in</code>으로 씁니다(조건 전체를 뒤집는 <code>not (...)</code>은 지원하지 않습니다).
            </DialogDescription>
          </DialogHeader>
          {help.data ? (
            <div className="flex flex-col gap-6">
              <section className="flex flex-col gap-2">
                <h3 className="text-sm font-semibold">예시 (누르면 입력됩니다)</h3>
                <ul className="flex flex-col gap-1.5">
                  {help.data.examples.map((example) => (
                    <li key={example.query}>
                      <button
                        type="button"
                        className="flex w-full flex-col gap-0.5 rounded-lg border px-3 py-2 text-left hover:bg-muted"
                        onClick={() => {
                          setDraft(example.query)
                          onApply(example.query)
                          setHelpOpen(false)
                        }}
                      >
                        <span className="text-sm">{example.title}</span>
                        <code className="text-xs text-muted-foreground">{example.query}</code>
                      </button>
                    </li>
                  ))}
                </ul>
              </section>
              <section className="flex flex-col gap-2">
                <h3 className="text-sm font-semibold">쓸 수 있는 필드</h3>
                <ul className="flex flex-col divide-y rounded-xl border">
                  {help.data.fields.map((field) => (
                    <li key={field.name} className="flex flex-col gap-1 px-3 py-2.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <code className="text-sm font-medium">{field.name}</code>
                        {field.aliases.length ? <span className="text-xs text-muted-foreground">별칭: {field.aliases.join(', ')}</span> : null}
                      </div>
                      <p className="text-xs text-muted-foreground">{field.description}</p>
                      <p className="font-mono text-xs text-muted-foreground">{field.operators.join('  ')}</p>
                    </li>
                  ))}
                </ul>
              </section>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">{help.isPending ? '불러오는 중…' : '문법 도움말을 불러오지 못했습니다.'}</p>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
