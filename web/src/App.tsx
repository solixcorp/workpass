import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'

function App() {
  return (
    <main className="flex min-h-svh items-center justify-center p-6">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle>Internal Auth</CardTitle>
          <CardDescription>Frontend scaffold is running.</CardDescription>
        </CardHeader>
        <CardContent>
          <Button asChild>
            <a href="/health">Check backend health</a>
          </Button>
        </CardContent>
      </Card>
    </main>
  )
}

export default App
