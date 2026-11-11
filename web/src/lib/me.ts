import { queryOptions } from '@tanstack/react-query'
import { apiFetch } from './api'

export type Notification = {
  id: string
  kind: string
  title: string
  body: string
  link: string | null
  createdAt: string
  readAt: string | null
}

export const notificationsQuery = queryOptions({
  queryKey: ['me', 'notifications'],
  queryFn: () => apiFetch<{ notifications: Notification[]; unread: number }>('/api/me/notifications'),
  refetchInterval: 60_000,
})

export type MyProfile = {
  name: string
  email: string
  login: string
  phoneNumber: string | null
  phoneVerified: boolean
  smsAvailable: boolean
  twoFactorEnabled: boolean
  fields: { title: string | null; department: string | null; organization: string | null; manager: string | null }
}

export const myProfileQuery = queryOptions({
  queryKey: ['me', 'profile'],
  queryFn: () => apiFetch<MyProfile>('/api/me/profile'),
})

export type MyActivity = {
  logins: Array<{ loginId: string; device: string; os: string; lastAt: string; location: string | null; ip: string | null; count: number; reported: boolean }>
  events: Array<{ id: string; at: string; type: string; outcome: string; byAdministrator: boolean }>
}

export const myActivityQuery = queryOptions({
  queryKey: ['me', 'activity'],
  queryFn: () => apiFetch<MyActivity>('/api/me/activity'),
})

export type NotificationCategory = 'security' | 'apps' | 'requests'

export type PagedNotification = Notification & { category: NotificationCategory }

export type NotificationPage = {
  notifications: PagedNotification[]
  unread: number
  total: number
  page: number
  limit: number
}

export type NotificationPreferences = {
  categories: Array<{ id: NotificationCategory; label: string; description: string; enabled: boolean; locked: boolean }>
}

export const notificationPreferencesQuery = queryOptions({
  queryKey: ['me', 'notification-preferences'],
  queryFn: () => apiFetch<NotificationPreferences>('/api/me/notification-preferences'),
})
