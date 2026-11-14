/**
 * The providers an administrator can choose for e-mail and SMS, the fields
 * each needs, and how a stored configuration becomes the environment variables
 * the senders already read. A secret field is never returned to the console.
 */

export type DeliveryKind = "email" | "sms";

export interface DeliveryField {
  key: string;
  label: string;
  secret?: boolean;
  required?: boolean;
  placeholder?: string;
  help?: string;
  type?: "text" | "number" | "select";
  options?: Array<{ value: string; label: string }>;
}

export interface DeliveryProviderSpec {
  id: string;
  label: string;
  description: string;
  fields: DeliveryField[];
}

/** Sender fields shared by every e-mail provider. */
const EMAIL_COMMON: DeliveryField[] = [
  { key: "from", label: "보내는 주소", required: true, placeholder: "no-reply@example.com", help: "공급자에서 발송을 허용한(도메인 인증을 마친) 주소여야 합니다." },
  { key: "fromName", label: "보내는 이름", placeholder: "예: Solix 계정" },
  { key: "replyTo", label: "회신 주소", placeholder: "support@example.com" },
];

export const EMAIL_PROVIDERS: DeliveryProviderSpec[] = [
  {
    id: "resend",
    label: "Resend",
    description: "HTTP API로 보냅니다. API 키 하나면 됩니다.",
    fields: [{ key: "apiKey", label: "API 키", secret: true, required: true, placeholder: "re_..." }],
  },
  {
    id: "smtp",
    label: "SMTP",
    description: "일반 SMTP 서버로 보냅니다.",
    fields: [
      { key: "host", label: "서버 주소", required: true, placeholder: "smtp.example.com" },
      { key: "port", label: "포트", type: "number", placeholder: "587" },
      {
        key: "security", label: "암호화", type: "select",
        options: [
          { value: "starttls", label: "STARTTLS (587 권장)" },
          { value: "implicit_tls", label: "TLS 직접 연결 (465)" },
          { value: "off", label: "암호화 없음 (권장하지 않음)" },
        ],
      },
      { key: "username", label: "사용자 이름" },
      { key: "password", label: "비밀번호", secret: true },
    ],
  },
  {
    id: "cloudflare",
    label: "Cloudflare Email Sending",
    description: "Cloudflare 계정의 이메일 발송 API로 보냅니다.",
    fields: [
      { key: "accountId", label: "계정 ID", required: true },
      { key: "apiToken", label: "API 토큰", secret: true, required: true, help: "Email Sending 권한이 있는 토큰이어야 합니다." },
    ],
  },
  {
    id: "maileroo",
    label: "Maileroo",
    description: "Maileroo 기본 이메일 API로 보냅니다.",
    fields: [{ key: "apiKey", label: "발송 키", secret: true, required: true }],
  },
  {
    id: "ses",
    label: "Amazon SES",
    description: "Amazon SES v2로 보냅니다.",
    fields: [
      { key: "region", label: "리전", required: true, placeholder: "ap-northeast-2" },
      { key: "accessKeyId", label: "액세스 키 ID", secret: true, required: true },
      { key: "secretAccessKey", label: "시크릿 액세스 키", secret: true, required: true },
      { key: "endpoint", label: "엔드포인트", placeholder: "비워 두면 리전의 기본 주소" },
    ],
  },
];

export const SMS_PROVIDERS: DeliveryProviderSpec[] = [
  {
    id: "solapi",
    label: "솔라피 (Solapi)",
    description: "국내 문자 발송 서비스입니다. 010으로 시작하는 번호로만 보낼 수 있습니다.",
    fields: [
      { key: "apiKey", label: "API Key", required: true, placeholder: "NCS..." },
      { key: "apiSecret", label: "API Secret", secret: true, required: true },
      { key: "from", label: "발신번호", required: true, placeholder: "0212345678", help: "솔라피에 등록한 발신번호만 쓸 수 있습니다." },
    ],
  },
  {
    id: "twilio",
    label: "Twilio",
    description: "해외 번호를 포함해 보낼 수 있습니다.",
    fields: [
      { key: "accountSid", label: "Account SID", required: true, placeholder: "AC..." },
      { key: "authToken", label: "Auth Token", secret: true, required: true },
      { key: "from", label: "발신번호 또는 Messaging Service SID", required: true, placeholder: "+12025550123 또는 MG..." },
    ],
  },
  {
    id: "webhook",
    label: "웹훅",
    description: "직접 만든 문자 게이트웨이에 JSON으로 요청합니다. 본문은 { to, code, text, sentAt }입니다.",
    fields: [
      { key: "url", label: "웹훅 주소", required: true, placeholder: "https://sms.example.com/send" },
      { key: "token", label: "Bearer 토큰", secret: true, help: "넣으면 Authorization 헤더로 함께 보냅니다." },
    ],
  },
];

export const CATALOG: Record<DeliveryKind, DeliveryProviderSpec[]> = { email: EMAIL_PROVIDERS, sms: SMS_PROVIDERS };

/** Fields every e-mail configuration carries next to the provider's own. */
export const COMMON_FIELDS: Record<DeliveryKind, DeliveryField[]> = { email: EMAIL_COMMON, sms: [] };

export function providerSpec(kind: DeliveryKind, id: string): DeliveryProviderSpec | null {
  return CATALOG[kind].find((spec) => spec.id === id) ?? null;
}

export function allFields(kind: DeliveryKind, id: string): DeliveryField[] {
  const spec = providerSpec(kind, id);
  return spec ? [...COMMON_FIELDS[kind], ...spec.fields] : [];
}

/** The environment variables a stored configuration stands in for. */
export function envFor(kind: DeliveryKind, provider: string, v: Record<string, string>): Record<string, string> {
  const get = (key: string) => v[key] ?? "";
  if (kind === "sms") {
    const base: Record<string, string> = { SMS_PROVIDER: provider, SMS_FROM: get("from"), MFA_SMS_WEBHOOK_URL: "" };
    if (provider === "twilio") return { ...base, SMS_TWILIO_ACCOUNT_SID: get("accountSid"), SMS_TWILIO_AUTH_TOKEN: get("authToken") };
    if (provider === "solapi") return { ...base, SMS_SOLAPI_API_KEY: get("apiKey"), SMS_SOLAPI_API_SECRET: get("apiSecret") };
    return { ...base, MFA_SMS_WEBHOOK_URL: get("url"), SMS_WEBHOOK_TOKEN: get("token") };
  }
  const from = get("from");
  const base: Record<string, string> = {
    MAIL_PROVIDER: provider, MAIL_FROM: from, INVITATION_EMAIL_FROM: from, MFA_OTP_EMAIL_FROM: from,
    MAIL_FROM_NAME: get("fromName"), MAIL_REPLY_TO: get("replyTo"),
    // A chosen provider replaces the development mailbox.
    INVITATION_EMAIL_WEBHOOK_URL: "", MFA_OTP_EMAIL_WEBHOOK_URL: "",
  };
  switch (provider) {
    case "resend": return { ...base, MAIL_RESEND_API_KEY: get("apiKey") };
    case "cloudflare": return { ...base, MAIL_CLOUDFLARE_ACCOUNT_ID: get("accountId"), MAIL_CLOUDFLARE_API_TOKEN: get("apiToken") };
    case "maileroo": return { ...base, MAIL_MAILEROO_API_KEY: get("apiKey") };
    case "ses":
      return { ...base, MAIL_SES_REGION: get("region"), MAIL_SES_ACCESS_KEY_ID: get("accessKeyId"), MAIL_SES_SECRET_ACCESS_KEY: get("secretAccessKey"), MAIL_SES_ENDPOINT: get("endpoint") };
    default: {
      const security = get("security") || "starttls";
      return {
        ...base, MAIL_SMTP_HOST: get("host"), MAIL_SMTP_PORT: get("port"), MAIL_SMTP_USERNAME: get("username"), MAIL_SMTP_PASSWORD: get("password"),
        MAIL_SMTP_SECURE: security === "implicit_tls" ? "true" : security === "off" ? "false" : "",
        MAIL_SMTP_STARTTLS: security === "starttls" ? "true" : "",
      };
    }
  }
}
