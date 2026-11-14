import { queryOptions } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'

/** The application that asked for the sign-in: its name and icon for the card header. */
export type AppBrand = { name: string; signInTitle: string; icon: string | null }

export const appBrandQuery = (oq: string) =>
  queryOptions({
    queryKey: ['app-brand', oq],
    queryFn: async () => {
      const body = await apiFetch<{ app: AppBrand | null }>('/api/config/login/app', {
        method: 'POST',
        body: JSON.stringify({ oq }),
      })
      return body.app
    },
    staleTime: Infinity,
  })
