import { queryOptions } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'

export type MfaMethodKey = 'totp' | 'otp' | 'hotp' | 'duo'

/** The enrollment screen as the server defines it. */
export type EnrollmentView = {
  title: string
  description: string
  required: boolean
  mustEnroll: boolean
  enabled: boolean
  passwordRequired: boolean
  passwordLabel: string
  requiredNotice: string
  methods: Array<{
    key: MfaMethodKey
    label: string
    description: string
    state: 'enrolled' | 'available' | 'blocked' | 'unconfigured'
    stateLabel: string
    actions: Array<'enroll' | 'add' | 'remove'>
  }>
  signIn: { title: string; description: string; requiredHeading: string; hint: string; setup: string; back: string }
  hotpTokens: Array<{ id: string; label: string; createdAt: string }>
  backupCodes: { available: boolean; label: string; description: string }
  disable: { available: boolean; label: string; description: string; blockedReason?: string }
  labels: Record<string, string>
}

export const enrollmentKey = ['mfa', 'enrollment'] as const

export const enrollmentQuery = queryOptions({
  queryKey: enrollmentKey,
  queryFn: () => apiFetch<EnrollmentView>('/api/mfa/enrollment'),
  staleTime: 0,
})
