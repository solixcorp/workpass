import { useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { CheckIcon } from 'lucide-react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Field, FieldContent, FieldDescription, FieldGroup, FieldLabel, FieldLegend, FieldSet } from '@/components/ui/field'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { CLIENT_TYPES, METHODS, type ClientType, type Method } from '@/lib/integrations'

/** Step one of adding an app: how it signs users in, and for OIDC what kind of app it is. */
export function NewIntegrationDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const navigate = useNavigate()
  const [method, setMethod] = useState<Method | null>(null)
  const [type, setType] = useState<Exclude<ClientType, 'service'> | null>(null)

  const [tab, setTab] = useState<'wizard' | 'classic'>('wizard')
  const ready = tab === 'wizard' || (method !== null && (method !== 'oidc' || type !== null))

  function next() {
    if (tab === 'wizard') {
      void navigate({ to: '/admin/applications/wizard' })
      onOpenChange(false)
      return
    }
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
        <Tabs value={tab} onValueChange={(value) => setTab(value as 'wizard' | 'classic')} className="gap-4">
          <TabsList variant="line">
            <TabsTrigger value="wizard">통합 마법사</TabsTrigger>
            <TabsTrigger value="classic">클래식</TabsTrigger>
          </TabsList>
          <TabsContent value="wizard">
            <div className="flex flex-col gap-4">
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-semibold">통합 마법사로 앱 연동 만들기</h3>
                <Badge variant="secondary">권장</Badge>
              </div>
              <p className="text-sm text-muted-foreground">필요한 기능을 켜고 세부 정보를 채우는 방식으로, 로그인 방식을 하나씩 고르지 않아도 됩니다.</p>
              <ul className="flex flex-col gap-2 text-sm">
                {['싱글 사인온(SSO): OIDC 또는 SAML', 'API 서비스 연동', '앱 로고와 설명'].map((line) => (
                  <li key={line} className="flex items-center gap-2">
                    <CheckIcon className="size-4 text-primary" />
                    {line}
                  </li>
                ))}
              </ul>
              <p className="text-xs text-muted-foreground">유니버설 로그아웃, 프로비저닝, 권한 관리는 이 시스템에 아직 없어 마법사에서 잠겨 있습니다.</p>
            </div>
          </TabsContent>
          <TabsContent value="classic">
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
          </TabsContent>
        </Tabs>
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
