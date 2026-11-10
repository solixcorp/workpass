export type StepUpMethodUi = {
  key: 'totp' | 'otp' | 'backup_code' | 'hotp' | 'duo_push'
  label: string
  fieldLabel: string
  input: 'otp6' | 'text' | 'push'
  send?: { label: string; hint: string }
}

/** Screen definition sent by the server for the second-factor challenge. */
export type StepUpUi = {
  title: string
  description: string
  submit: { label: string }
  methods: StepUpMethodUi[]
  alternatives: Array<{ label: string; action: 'cancel' }>
  banner: {
    title: string
    description: string
    expiredDescription: string
    action: string
    dialogTitle: string
    dialogDescription: string
  }
  messages: { push_denied: string; invalid_code: string; rate_limited: string; record_failed: string }
}
