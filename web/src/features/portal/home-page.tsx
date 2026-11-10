import { useQuery } from '@tanstack/react-query'
import { AppWindowIcon, ExternalLinkIcon } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from '@/components/ui/empty'
import {
  Item,
  ItemActions,
  ItemContent,
  ItemDescription,
  ItemGroup,
  ItemMedia,
  ItemTitle,
} from '@/components/ui/item'
import { Skeleton } from '@/components/ui/skeleton'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { applicationsQuery, sessionQuery, type PortalApplication } from '@/lib/queries'

const PROTOCOL_LABELS: Record<string, string> = {
  bookmark: '링크',
  saml: 'SAML',
  wsfed: 'WS-Fed',
  oidc: 'OIDC',
  swa: 'SWA',
}

function groupByCategory(applications: PortalApplication[]) {
  const groups = new Map<string, PortalApplication[]>()
  for (const application of applications) {
    const key = application.categoryGroup?.trim() || '앱'
    groups.set(key, [...(groups.get(key) ?? []), application])
  }
  return [...groups.entries()]
}

function ApplicationItem({ application }: { application: PortalApplication }) {
  const content = (
    <>
      <ItemMedia variant={application.icon ? 'image' : 'icon'}>
        {application.icon ? (
          <img src={application.icon} alt="" loading="lazy" />
        ) : (
          <AppWindowIcon />
        )}
      </ItemMedia>
      <ItemContent>
        <ItemTitle>{application.name}</ItemTitle>
        {application.description ? (
          <ItemDescription>{application.description}</ItemDescription>
        ) : null}
      </ItemContent>
      <ItemActions>
        <Badge variant="secondary">
          {PROTOCOL_LABELS[application.protocol] ?? application.protocol}
        </Badge>
        {application.launchUrl ? <ExternalLinkIcon className="text-muted-foreground" /> : null}
      </ItemActions>
    </>
  )

  if (!application.launchUrl) {
    return <Item variant="muted">{content}</Item>
  }
  return (
    <Item variant="muted" asChild>
      <a href={application.launchUrl} target="_blank" rel="noopener noreferrer">
        {content}
      </a>
    </Item>
  )
}

export function PortalHomePage() {
  const { data: session } = useQuery(sessionQuery)
  const { data: applications, isPending, error } = useQuery(applicationsQuery)
  const firstName = session?.user.name?.split(' ')[0] ?? ''

  return (
    <div className="mx-auto flex w-full max-w-4xl flex-col gap-8">
      <h1 className="text-2xl font-semibold">
        {firstName ? `${firstName}님, 안녕하세요` : '내 앱'}
      </h1>

      {error ? (
        <Alert variant="destructive">
          <AlertDescription>앱 목록을 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : isPending ? (
        <div className="grid gap-2 sm:grid-cols-2">
          {Array.from({ length: 4 }, (_, index) => (
            <Skeleton key={index} className="h-16 rounded-lg" />
          ))}
        </div>
      ) : applications.length === 0 ? (
        <Empty>
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <AppWindowIcon />
            </EmptyMedia>
            <EmptyTitle>사용할 수 있는 앱이 없습니다</EmptyTitle>
            <EmptyDescription>
              관리자가 앱을 등록하거나 접근 권한을 부여하면 여기에 표시됩니다.
            </EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        groupByCategory(applications).map(([category, items]) => (
          <section key={category} className="flex flex-col gap-3">
            <h2 className="text-sm font-medium text-muted-foreground">{category}</h2>
            <ItemGroup className="grid gap-2 sm:grid-cols-2">
              {items.map((application) => (
                <ApplicationItem key={application.slug} application={application} />
              ))}
            </ItemGroup>
          </section>
        ))
      )}
    </div>
  )
}
