import { useMutation, useQueryClient } from '@tanstack/react-query'
import { CrosshairIcon } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Spinner } from '@/components/ui/spinner'
import { ApiError, apiFetch } from '@/lib/api'
import { currentPosition } from '@/lib/location'
import type { Place } from './types'

/** One allowed place: a name, a centre and a radius. */
export function PlaceDialog({ open, place, onClose }: { open: boolean; place: Place | null; onClose: () => void }) {
  const queryClient = useQueryClient()
  const [name, setName] = useState(place?.name ?? '')
  const [latitude, setLatitude] = useState(place ? String(place.latitude) : '')
  const [longitude, setLongitude] = useState(place ? String(place.longitude) : '')
  const [radius, setRadius] = useState(place ? String(place.radiusM) : '500')
  const [failure, setFailure] = useState<string | null>(null)
  const [locating, setLocating] = useState(false)

  const save = useMutation({
    mutationFn: () =>
      apiFetch(place ? `/api/admin/location/places/${place.id}` : '/api/admin/location/places', {
        method: place ? 'PUT' : 'POST',
        body: JSON.stringify({ name, latitude: Number(latitude), longitude: Number(longitude), radiusM: Number(radius), enabled: place?.enabled ?? true }),
      }),
    onSuccess: async () => {
      toast.success(place ? '장소를 저장했습니다.' : '장소를 추가했습니다.')
      await queryClient.invalidateQueries({ queryKey: ['admin', 'location'] })
      onClose()
    },
    onError: (error) => setFailure(error instanceof ApiError && /[가-힣]/.test(error.message) ? error.message : '저장하지 못했습니다.'),
  })

  async function useMyPosition() {
    setLocating(true)
    setFailure(null)
    try {
      const position = await currentPosition()
      setLatitude(position.coords.latitude.toFixed(5))
      setLongitude(position.coords.longitude.toFixed(5))
    } catch {
      setFailure('현재 위치를 가져오지 못했습니다. 브라우저의 위치 권한을 확인하세요.')
    } finally {
      setLocating(false)
    }
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    save.mutate()
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !next && !save.isPending && onClose()}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={submit} className="flex flex-col gap-4">
          <DialogHeader>
            <DialogTitle>{place ? '장소 수정' : '장소 추가'}</DialogTitle>
            <DialogDescription>로그인을 허용할 곳의 중심 좌표와 반경입니다.</DialogDescription>
          </DialogHeader>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="place-name">이름</FieldLabel>
              <Input id="place-name" value={name} maxLength={80} onChange={(event) => setName(event.target.value)} placeholder="예: 서울 본사" />
            </Field>
            <div className="grid grid-cols-2 gap-3">
              <Field>
                <FieldLabel htmlFor="place-lat">위도</FieldLabel>
                <Input id="place-lat" inputMode="decimal" value={latitude} onChange={(event) => setLatitude(event.target.value)} placeholder="37.5665" />
              </Field>
              <Field>
                <FieldLabel htmlFor="place-lon">경도</FieldLabel>
                <Input id="place-lon" inputMode="decimal" value={longitude} onChange={(event) => setLongitude(event.target.value)} placeholder="126.9780" />
              </Field>
            </div>
            <div>
              <Button type="button" variant="outline" size="sm" disabled={locating} onClick={useMyPosition}>
                {locating ? <Spinner data-icon="inline-start" /> : <CrosshairIcon data-icon="inline-start" />}
                내 현재 위치 넣기
              </Button>
            </div>
            <Field>
              <FieldLabel htmlFor="place-radius">반경 (미터)</FieldLabel>
              <Input id="place-radius" inputMode="numeric" value={radius} onChange={(event) => setRadius(event.target.value)} />
              <FieldDescription>50m에서 500,000m(500km)까지입니다. 건물 하나는 200~500m, 도시 전체는 20,000m 안팎입니다.</FieldDescription>
            </Field>
          </FieldGroup>
          {failure ? (
            <Alert variant="destructive">
              <AlertDescription>{failure}</AlertDescription>
            </Alert>
          ) : null}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={save.isPending} onClick={onClose}>
              취소
            </Button>
            <Button type="submit" disabled={save.isPending || !name.trim() || !latitude || !longitude}>
              {save.isPending ? <Spinner data-icon="inline-start" /> : null}
              저장
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
