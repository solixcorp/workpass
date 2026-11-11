import { useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Field, FieldContent, FieldDescription, FieldGroup, FieldLabel, FieldLegend, FieldSet } from '@/components/ui/field'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { CLIENT_TYPES, METHODS, type ClientType, type Method } from '@/lib/integrations'

/** Step one of adding an app: how it signs users in, and for OIDC what kind of app it is. */
export function NewIntegrationDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const navigate = useNavigate()
  const [method, setMethod] = useState<Method | null>(null)
  const [type, setType] = useState<Exclude<ClientType, 'service'> | null>(null)

  const ready = method !== null && (method !== 'oidc' || type !== null)

  function next() {
    if (!method) return
    void navigate({
      to: '/admin/applications/new',
      search: { method, ...(method === 'oidc' && type ? { type } : {}) },
    })
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>앱 연동 만들기</DialogTitle>
          <DialogDescription>사용자가 이 앱에 어떻게 로그인할지 고르세요. 만든 뒤에는 방식을 바꿀 수 없습니다.</DialogDescription>
        </DialogHeader>
        <FieldGroup>
          <FieldSet>
            <FieldLegend>로그인 방식</FieldLegend>
            <RadioGroup value={method ?? ''} onValueChange={(value) => setMethod(value as Method)}>
              {METHODS.map((entry) => (
                <Field key={entry.value} orientation="horizontal">
                  <RadioGroupItem id={`method-${entry.value}`} value={entry.value} />
                  <FieldContent>
                    <FieldLabel htmlFor={`method-${entry.value}`}>{entry.label}</FieldLabel>
                    <FieldDescription>{entry.description}</FieldDescription>
                  </FieldContent>
                </Field>
              ))}
            </RadioGroup>
          </FieldSet>
          {method === 'oidc' ? (
            <FieldSet>
              <FieldLegend>앱 유형</FieldLegend>
              <FieldDescription>
                유형에 맞게 설정 항목과 권장 구성이 정해집니다.
              </FieldDescription>
              <RadioGroup value={type ?? ''} onValueChange={(value) => setType(value as typeof type)}>
                {CLIENT_TYPES.map((entry) => (
                  <Field key={entry.value} orientation="horizontal">
                    <RadioGroupItem id={`type-${entry.value}`} value={entry.value} />
                    <FieldContent>
                      <FieldLabel htmlFor={`type-${entry.value}`}>{entry.label}</FieldLabel>
                      <FieldDescription>{entry.description}</FieldDescription>
                    </FieldContent>
                  </Field>
                ))}
              </RadioGroup>
            </FieldSet>
          ) : null}
        </FieldGroup>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            취소
          </Button>
          <Button type="button" disabled={!ready} onClick={next}>
            다음
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
