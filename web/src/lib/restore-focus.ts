let lastOutside: HTMLElement | null = null

if (typeof document !== 'undefined') {
  document.addEventListener(
    'focusin',
    (event) => {
      const target = event.target
      if (target instanceof HTMLElement && !target.closest('[role="dialog"], [role="alertdialog"], [data-radix-popper-content-wrapper]')) {
        lastOutside = target
      }
    },
    true,
  )
}

/**
 * Dialogs opened by state instead of a trigger do not know which control opened them, so keyboard
 * focus falls to the page body when they close. The last control focused outside any dialog is the
 * one that opened it; hand focus back to it on close.
 */
export function useRestoreFocus() {
  return (event: Event) => {
    if (lastOutside?.isConnected) {
      event.preventDefault()
      lastOutside.focus()
    }
  }
}
