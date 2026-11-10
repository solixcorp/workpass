import { AuthShell } from '@/components/auth-shell'

/** Shown while a route loads: the sign-in card with its body folded shut. */
export function LoadingScreen() {
  return <AuthShell folded />
}
