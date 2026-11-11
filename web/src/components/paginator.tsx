import { ChevronLeftIcon, ChevronRightIcon, ChevronsLeftIcon, ChevronsRightIcon } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'

/** Page numbers around the current one, with the first and last page and gaps shown as `null`. */
function pageWindow(page: number, pages: number): Array<number | null> {
  const wanted = new Set([1, pages, page - 1, page, page + 1])
  const sorted = [...wanted].filter((n) => n >= 1 && n <= pages).sort((a, b) => a - b)
  const out: Array<number | null> = []
  sorted.forEach((n, index) => {
    if (index > 0 && n - sorted[index - 1]! > 1) out.push(null)
    out.push(n)
  })
  return out
}

/** Numbered pages with first/previous/next/last, a total, and an optional page-size choice. */
export function Paginator({
  page,
  pageSize,
  total,
  onPage,
  onPageSize,
  sizes = [25, 50, 100],
}: {
  page: number
  pageSize: number
  total: number
  onPage: (page: number) => void
  onPageSize?: (size: number) => void
  sizes?: number[]
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize))
  const first = total === 0 ? 0 : (page - 1) * pageSize + 1
  const last = Math.min(total, page * pageSize)
  return (
    <nav aria-label="페이지" className="flex flex-wrap items-center justify-between gap-3 text-sm">
      <span className="text-muted-foreground tabular-nums">
        총 {total.toLocaleString('ko-KR')}건{total > 0 ? ` 중 ${first.toLocaleString('ko-KR')}–${last.toLocaleString('ko-KR')}` : ''}
      </span>
      <div className="flex items-center gap-1">
        <Button variant="ghost" size="icon-sm" aria-label="첫 페이지" disabled={page <= 1} onClick={() => onPage(1)}>
          <ChevronsLeftIcon />
        </Button>
        <Button variant="ghost" size="icon-sm" aria-label="이전 페이지" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          <ChevronLeftIcon />
        </Button>
        {pageWindow(page, pages).map((entry, index) =>
          entry === null ? (
            <span key={`gap-${index}`} className="px-1 text-muted-foreground" aria-hidden>
              …
            </span>
          ) : (
            <Button key={entry} variant={entry === page ? 'outline' : 'ghost'} size="icon-sm" aria-label={`${entry}페이지`} aria-current={entry === page ? 'page' : undefined} onClick={() => onPage(entry)}>
              {entry}
            </Button>
          ),
        )}
        <Button variant="ghost" size="icon-sm" aria-label="다음 페이지" disabled={page >= pages} onClick={() => onPage(page + 1)}>
          <ChevronRightIcon />
        </Button>
        <Button variant="ghost" size="icon-sm" aria-label="마지막 페이지" disabled={page >= pages} onClick={() => onPage(pages)}>
          <ChevronsRightIcon />
        </Button>
      </div>
      {onPageSize ? (
        <Select value={String(pageSize)} onValueChange={(value) => onPageSize(Number(value))}>
          <SelectTrigger aria-label="페이지당 개수" className="w-32">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              {sizes.map((size) => (
                <SelectItem key={size} value={String(size)}>
                  {size}개씩 보기
                </SelectItem>
              ))}
            </SelectGroup>
          </SelectContent>
        </Select>
      ) : null}
    </nav>
  )
}
