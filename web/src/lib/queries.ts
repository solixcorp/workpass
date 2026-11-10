import { queryOptions } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { authClient, type AuthSession } from '@/lib/auth-client'
import type { StepUpUi } from '@/lib/step-up'

export const sessionQuery = queryOptions({
  queryKey: ['session'],
  queryFn: async (): Promise<AuthSession | null> => {
    const { data, error } = await authClient.getSession()
    if (error) {
      if (error.status === 401) return null
      throw new Error(error.message ?? 'Session lookup failed')
    }
    return data ?? null
  },
  staleTime: 30_000,
})

export type StepUpChallenge =
  | { required: false; state: 'none' | 'satisfied' }
  | {
      required: true
      state: 'pending' | 'expired'
      reasons: string[]
      expiresAt: string | null
      methods: string[]
      ui: StepUpUi
    }

export const stepUpQuery = queryOptions({
  queryKey: ['step-up'],
  queryFn: () => apiFetch<StepUpChallenge>('/api/security/step-up/challenge'),
  staleTime: 10_000,
})

export type PortalApplication = {
  slug: string
  name: string
  description: string | null
  protocol: string
  launchUrl: string | null
  categoryGroup: string | null
  icon: string | null
}

export const applicationsQuery = queryOptions({
  queryKey: ['applications'],
  queryFn: async () => {
    const body = await apiFetch<{ applications: PortalApplication[] }>('/api/applications')
    return body.applications
  },
})
