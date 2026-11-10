import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, Outlet, useNavigate, useRouterState } from '@tanstack/react-router'
import {
  ActivityIcon,
  AppWindowIcon,
  BlocksIcon,
  ChevronsUpDownIcon,
  LayoutDashboardIcon,
  LogOutIcon,
  SettingsIcon,
  ShieldCheckIcon,
  UsersIcon,
} from 'lucide-react'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
} from '@/components/ui/sidebar'
import { authClient, isAdministrator } from '@/lib/auth-client'
import { sessionQuery } from '@/lib/queries'
import { loginConfigQuery } from '@/lib/fingerprint'
import { StepUpBanner } from '@/features/auth/step-up-banner'

type NavItem = { to: string; label: string; icon: typeof AppWindowIcon; exact?: boolean }

const PORTAL_NAV: NavItem[] = [
  { to: '/', label: '내 앱', icon: AppWindowIcon, exact: true },
  { to: '/security', label: '보안', icon: ShieldCheckIcon },
]

const ADMIN_NAV: NavItem[] = [
  { to: '/admin', label: '개요', icon: LayoutDashboardIcon, exact: true },
  { to: '/admin/users', label: '사용자', icon: UsersIcon },
  { to: '/admin/applications', label: '앱', icon: BlocksIcon },
  { to: '/admin/audit', label: '감사 로그', icon: ActivityIcon },
  { to: '/admin/settings', label: '설정', icon: SettingsIcon },
]

function initials(name: string | undefined, email: string | undefined): string {
  const source = (name || email || '?').trim()
  return source.slice(0, 2).toUpperCase()
}

function NavGroup({ label, items }: { label: string; items: NavItem[] }) {
  const pathname = useRouterState({ select: (state) => state.location.pathname })
  return (
    <SidebarGroup>
      <SidebarGroupLabel>{label}</SidebarGroupLabel>
      <SidebarGroupContent>
        <SidebarMenu>
          {items.map((item) => {
            const active = item.exact ? pathname === item.to : pathname.startsWith(item.to)
            return (
              <SidebarMenuItem key={item.to}>
                <SidebarMenuButton asChild isActive={active} tooltip={item.label}>
                  <Link to={item.to}>
                    <item.icon />
                    <span>{item.label}</span>
                  </Link>
                </SidebarMenuButton>
              </SidebarMenuItem>
            )
          })}
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  )
}

export function AppShell() {
  const { data: session } = useQuery(sessionQuery)
  const { data: config } = useQuery(loginConfigQuery)
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const admin = isAdministrator(session)
  const user = session?.user

  async function signOut() {
    await authClient.signOut()
    queryClient.clear()
    await navigate({ to: '/login', replace: true })
  }

  return (
    <SidebarProvider>
      <Sidebar collapsible="icon">
        <SidebarHeader>
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton size="lg" asChild>
                <Link to="/">
                  <div className="flex flex-col gap-0.5 leading-none">
                    <span className="font-medium">WorkPass</span>
                    <span className="text-xs text-muted-foreground">{config?.organization.name}</span>
                  </div>
                </Link>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarHeader>
        <SidebarContent>
          <NavGroup label="포털" items={PORTAL_NAV} />
          {admin ? <NavGroup label="관리" items={ADMIN_NAV} /> : null}
        </SidebarContent>
        <SidebarFooter>
          <SidebarMenu>
            <SidebarMenuItem>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <SidebarMenuButton size="lg">
                    <Avatar size="sm">
                      <AvatarFallback>{initials(user?.name, user?.email)}</AvatarFallback>
                    </Avatar>
                    <div className="flex min-w-0 flex-col gap-0.5 leading-none">
                      <span className="truncate font-medium">{user?.name}</span>
                      <span className="truncate text-xs text-muted-foreground">{user?.email}</span>
                    </div>
                    <ChevronsUpDownIcon className="ml-auto" />
                  </SidebarMenuButton>
                </DropdownMenuTrigger>
                <DropdownMenuContent side="top" align="start" className="w-56">
                  <DropdownMenuLabel className="truncate">{user?.email}</DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  <DropdownMenuGroup>
                    <DropdownMenuItem onSelect={signOut}>
                      <LogOutIcon />
                      로그아웃
                    </DropdownMenuItem>
                  </DropdownMenuGroup>
                </DropdownMenuContent>
              </DropdownMenu>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarFooter>
      </Sidebar>
      <SidebarInset>
        <header className="flex h-12 shrink-0 items-center gap-2 px-4">
          <SidebarTrigger className="-ml-1" />
        </header>
        <div className="flex flex-1 flex-col gap-6 px-4 pb-10 md:px-8">
          <StepUpBanner />
          <Outlet />
        </div>
      </SidebarInset>
    </SidebarProvider>
  )
}
