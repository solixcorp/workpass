/**
 * Screen definition for the second-factor (step-up) challenge. Every surface
 * that shows the challenge (the sign-in screen and the portal banner) renders
 * this as-is, so wording, offered methods and field shapes live server-side.
 */

export interface StepUpMethodUi {
  key: "totp" | "otp" | "backup_code" | "hotp" | "duo_push";
  label: string;
  fieldLabel: string;
  /** otp6: six one-time digits; text: free-form code; push: approve on a device. */
  input: "otp6" | "text" | "push";
  /** Present when the code must be requested before it can be entered. */
  send?: { label: string; hint: string };
}

export interface StepUpUi {
  title: string;
  description: string;
  submit: { label: string };
  methods: StepUpMethodUi[];
  alternatives: Array<{ label: string; action: "cancel" }>;
  banner: {
    title: string;
    description: string;
    expiredDescription: string;
    action: string;
    dialogTitle: string;
    dialogDescription: string;
  };
  messages: {
    push_denied: string;
    invalid_code: string;
    rate_limited: string;
    record_failed: string;
  };
}

const METHOD_UI: Record<StepUpMethodUi["key"], StepUpMethodUi> = {
  totp: { key: "totp", label: "인증 앱", fieldLabel: "6자리 코드", input: "otp6" },
  otp: {
    key: "otp",
    label: "일회용 코드",
    fieldLabel: "6자리 코드",
    input: "otp6",
    send: { label: "코드 보내기", hint: "등록된 휴대폰 또는 이메일로 일회용 코드를 보냅니다." },
  },
  backup_code: { key: "backup_code", label: "백업 코드", fieldLabel: "백업 코드", input: "text" },
  hotp: { key: "hotp", label: "보안 토큰", fieldLabel: "토큰의 6자리 코드", input: "otp6" },
  duo_push: {
    key: "duo_push",
    label: "Duo 푸시",
    fieldLabel: "",
    input: "push",
    send: { label: "푸시 보내기", hint: "휴대폰의 Duo 앱에서 승인하세요." },
  },
};

export function stepUpUi(methods: string[]): StepUpUi {
  const offered = methods.filter((method): method is StepUpMethodUi["key"] => method in METHOD_UI);
  // Backup codes ride on the authenticator-app enrollment.
  if (offered.includes("totp") && !offered.includes("backup_code")) offered.push("backup_code");
  return {
    title: "추가 인증",
    description: "새로운 기기나 위치에서 로그인했습니다. 2차 인증을 완료하세요.",
    submit: { label: "확인" },
    methods: offered.map((key) => METHOD_UI[key]),
    alternatives: [{ label: "로그인 화면으로 돌아가기", action: "cancel" }],
    banner: {
      title: "추가 인증이 필요합니다",
      description: "새로운 위치나 기기에서 로그인했습니다. 앱을 열기 전에 2차 인증을 완료하세요.",
      expiredDescription: "추가 인증 기한이 지났습니다. 다시 로그인하세요.",
      action: "인증하기",
      dialogTitle: "추가 인증",
      dialogDescription: "등록한 인증 수단으로 본인을 확인하세요.",
    },
    messages: {
      push_denied: "승인이 거절되었거나 시간이 지났습니다.",
      invalid_code: "코드가 올바르지 않거나 만료되었습니다.",
      rate_limited: "시도가 너무 많습니다. 잠시 후 다시 시도하세요.",
      record_failed: "인증 결과를 기록하지 못했습니다. 다시 시도하세요.",
    },
  };
}
