import { CheckIcon, CopyIcon, PlusIcon, XIcon } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Skeleton } from '@/components/ui/skeleton'
import { GRANT_LABELS, type DirectoryGroup, type GrantKey } from '@/lib/integrations'

/** A settings row: what it is on the left, the controls on the right. */
export function SettingRow({
  title,
  description,
  children,
}: {
  title: string
  description?: ReactNode
  children: ReactNode
}) {
  return (
    <div className="grid gap-3 py-5 md:grid-cols-[16rem_minmax(0,1fr)] md:gap-8">
      <div className="flex flex-col gap-1">
        <h3 className="text-sm font-medium">{title}</h3>
        {description ? <p className="text-xs text-muted-foreground">{description}</p> : null}
      </div>
      <div className="flex min-w-0 flex-col gap-3">{children}</div>
    </div>
  )
}

export function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="flex flex-col rounded-2xl border bg-card px-6 py-2">
      <h2 className="pt-4 text-sm font-semibold">{title}</h2>
      <div className="divide-y">{children}</div>
    </section>
  )
}

export function CopyField({ value, label, mono = true }: { value: string; label: string; mono?: boolean }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="flex items-center gap-2">
      <Input aria-label={label} readOnly value={value} className={mono ? 'h-8 font-mono text-xs md:text-xs' : 'h-8 text-xs md:text-xs'} />
      <Button
        type="button"
        variant="outline"
        size="icon"
        aria-label={`${label} 복사`}
        onClick={async () => {
          await navigator.clipboard.writeText(value)
          setCopied(true)
          setTimeout(() => setCopied(false), 1500)
        }}
      >
        {copied ? <CheckIcon /> : <CopyIcon />}
      </Button>
    </div>
  )
}

/** A list of addresses: one input each, a remove button, and an add button. */
export function UriListField({
  label,
  values,
  onChange,
  placeholder,
  max = 10,
  allowEmpty = false,
  addLabel = '주소 추가',
}: {
  label: string
  values: string[]
  onChange: (values: string[]) => void
  placeholder?: string
  max?: number
  allowEmpty?: boolean
  addLabel?: string
}) {
  const rows = values.length ? values : ['']
  return (
    <div className="flex flex-col gap-2">
      {rows.map((value, index) => (
        <div key={index} className="flex items-center gap-2">
          <Input
            aria-label={`${label} ${index + 1}`}
            autoComplete="off"
            spellCheck={false}
            placeholder={placeholder}
            value={value}
            onChange={(event) => onChange(rows.map((row, i) => (i === index ? event.target.value : row)))}
          />
          <Button
            type="button"
            variant="outline"
            size="icon"
            aria-label={`${label} ${index + 1} 삭제`}
            disabled={rows.length === 1 && !allowEmpty && !value}
            onClick={() => onChange(rows.filter((_, i) => i !== index))}
          >
            <XIcon />
          </Button>
        </div>
      ))}
      <div>
        <Button type="button" variant="outline" size="sm" disabled={rows.length >= max} onClick={() => onChange([...rows, ''])}>
          <PlusIcon data-icon="inline-start" />
          {addLabel}
        </Button>
      </div>
    </div>
  )
}

export function GrantsField({
  options,
  locked,
  value,
  onChange,
}: {
  options: GrantKey[]
  locked: GrantKey[]
  value: GrantKey[]
  onChange: (next: GrantKey[]) => void
}) {
  return (
    <FieldGroup className="gap-3">
      {options.map((key) => {
        const isLocked = locked.includes(key)
        const checked = isLocked || value.includes(key)
        return (
          <Field key={key} orientation="horizontal">
            <Checkbox
              id={`grant-${key}`}
              checked={checked}
              disabled={isLocked}
              onCheckedChange={(on) => onChange(on === true ? [...new Set([...value, key])] : value.filter((g) => g !== key))}
            />
            <div className="flex flex-col gap-0.5">
              <FieldLabel htmlFor={`grant-${key}`}>{GRANT_LABELS[key].label}</FieldLabel>
              <FieldDescription>{GRANT_LABELS[key].description}</FieldDescription>
            </div>
          </Field>
        )
      })}
    </FieldGroup>
  )
}

export type AssignChoice = 'everyone' | 'groups' | 'later'

/** Who gets the app: everyone, chosen groups, or nobody yet. */
export function AssignmentChooser({
  choice,
  onChoice,
  groups,
  loading,
  selected,
  onSelected,
  allowLater,
}: {
  choice: AssignChoice
  onChoice: (choice: AssignChoice) => void
  groups: DirectoryGroup[] | undefined
  loading: boolean
  selected: string[]
  onSelected: (ids: string[]) => void
  allowLater: boolean
}) {
  return (
    <div className="flex flex-col gap-4">
      <RadioGroup value={choice} onValueChange={(value) => onChoice(value as AssignChoice)}>
        <Field orientation="horizontal">
          <RadioGroupItem id="assign-everyone" value="everyone" />
          <FieldLabel htmlFor="assign-everyone">조직의 모든 사용자에게 허용</FieldLabel>
        </Field>
        <Field orientation="horizontal">
          <RadioGroupItem id="assign-groups" value="groups" />
          <FieldLabel htmlFor="assign-groups">선택한 그룹에게만 허용</FieldLabel>
        </Field>
        {allowLater ? (
          <Field orientation="horizontal">
            <RadioGroupItem id="assign-later" value="later" />
            <FieldLabel htmlFor="assign-later">지금은 할당하지 않음 (앱은 꺼진 상태로 만들어집니다)</FieldLabel>
          </Field>
        ) : null}
      </RadioGroup>
      {choice === 'groups' ? (
        loading ? (
          <Skeleton className="h-16 rounded-lg" />
        ) : groups && groups.length > 0 ? (
          <FieldGroup className="gap-3 rounded-lg border p-4">
            {groups.map((group) => (
              <Field key={group.id} orientation="horizontal">
                <Checkbox
                  id={`assign-group-${group.id}`}
                  checked={selected.includes(group.id)}
                  onCheckedChange={(on) =>
                    onSelected(on === true ? [...selected, group.id] : selected.filter((id) => id !== group.id))
                  }
                />
                <FieldLabel htmlFor={`assign-group-${group.id}`}>{group.name}</FieldLabel>
              </Field>
            ))}
          </FieldGroup>
        ) : (
          <p className="text-sm text-muted-foreground">그룹이 없습니다. 그룹 메뉴에서 먼저 만드세요.</p>
        )
      ) : null}
    </div>
  )
}
