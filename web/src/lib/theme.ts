import { useSyncExternalStore } from 'react'

export type ThemeChoice = 'light' | 'dark' | 'system'

const KEY = 'workpass-theme'
const listeners = new Set<() => void>()
const media = typeof window !== 'undefined' ? window.matchMedia('(prefers-color-scheme: dark)') : null

function stored(): ThemeChoice {
  try {
    const value = localStorage.getItem(KEY)
    return value === 'light' || value === 'dark' ? value : 'system'
  } catch {
    return 'system'
  }
}

function apply(choice: ThemeChoice) {
  const dark = choice === 'dark' || (choice === 'system' && media?.matches === true)
  document.documentElement.classList.toggle('dark', dark)
  document.documentElement.style.colorScheme = dark ? 'dark' : 'light'
}

/** Run once before the first render so the page never flashes the wrong theme. */
export function initTheme() {
  apply(stored())
  media?.addEventListener('change', () => {
    if (stored() === 'system') apply('system')
    listeners.forEach((listener) => listener())
  })
}

export function setTheme(choice: ThemeChoice) {
  try {
    if (choice === 'system') localStorage.removeItem(KEY)
    else localStorage.setItem(KEY, choice)
  } catch {
    // Without storage the choice only lasts for this page.
  }
  apply(choice)
  listeners.forEach((listener) => listener())
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function useThemeChoice(): ThemeChoice {
  return useSyncExternalStore(subscribe, stored, () => 'system')
}

/** What is on screen right now, for components that need to know (the toast). */
export function useResolvedTheme(): 'light' | 'dark' {
  const choice = useThemeChoice()
  return choice === 'dark' || (choice === 'system' && media?.matches === true) ? 'dark' : 'light'
}
