# 프론트엔드 작업 지시서: 로그인을 OPAQUE(RFC 9807) 제로 지식 패스워드 방식으로 전환

> 2026-11-10. 백엔드 쪽 평문 로그인 경로(`/api/auth/sign-in/email`, `/api/auth/sign-in/username`)는 **이미 404로 차단**되어 있습니다. 스프레드시트로 대충 때우지 말고 아래 계약 그대로 구현하세요. 궁금한 건 서버 코드 `src/auth/opaque-routes.ts`, `src/auth/opaque.ts`, 참고 클라이언트 예제 `scripts/opaque-smoke.ts`를 먼저 읽으세요.

## 0. 목표

- 로그인 POST 요청에 **비밀번호 평문(또는 그 어떤 비밀번호 파생 값)이 절대 담기지 않아야** 합니다.
- 비밀번호는 브라우저 안에서 OPAQUE 클라이언트 연산(opaque-ts)에만 쓰이고, 네트워크로는 KE1/KE3 같은 프로토콜 메시지(base64url)만 나갑니다.
- 서버는 이미 구현·검증 완료(`scripts/opaque-smoke.ts`가 통과). **프론트엔드에 클라이언트 절반이 없는 상태**입니다.

## 1. 의존성

`web/package.json`에 추가 후 설치:

```json
"@cloudflare/opaque-ts": "^0.7.5"
```

같은 패키지가 서버와 브라우저 양쪽에서 동작합니다(WebCrypto + @noble/hashes 기반, WASM 없음). 버전은 루트 `package.json`에 설치된 서버 쪽과 동일하게 맞추세요(프로토콜 메시지 직렬화 호환성 때문에 메이저/마이너 버전이 서로 다르면 안 됨).

## 2. 서버 API 계약 (이미 구현됨 — 수정 금지, 여기 있는 그대로 사용)

모든 OPAQUE 메시지는 JSON 필드 안의 **base64url 문자열**(`+`,`/` → `-`,`_`, 패딩 제거, 1~4096자)입니다.

### 2.1 `POST /api/opaque/auth/start` (비로그인 공개, no-store)

```jsonc
// 요청
{ "username": "trim된 식별자(이메일 또는 username, 소문자로 정규화 권장)", "ke1": "<base64url KE1>" }
// 응답 200
{ "ke2": "<base64url>", "credentialIdentifier": "<identity>", "serverIdentity": "<origin>", "transcriptId": "<uuid>" }
// 오류 400 {"error": ...} / 429 {"error": "..."} (IP당 분당 30회 공유 버킷)
```

- 서버는 미등록 사용자여도 실패 응답을 내지 않고 가짜 레코드로 정상 KE2를 만듭니다(계정 열거 방지).
- **미등록 여부는 판별할 수 없습니다(의도된 동작).** 응답의 `credentialIdentifier`는 요청한 식별자(정규화된 이메일)를 그대로 돌려주며, 등록·미등록·존재하지 않는 계정 모두 같은 모양과 같은 값입니다. 클라이언트는 `authFinish`에 서버 값이 아니라 **사용자가 입력한 식별자**를 넘기세요. 이메일로 등록된 레코드만 쓰이므로 로그인 식별자는 이메일입니다.
- 트랜스크립트는 서버에서 **단 1회용, TTL 120초**. 실패 후 재시도는 항상 `auth/start`부터 다시.

### 2.2 `POST /api/opaque/auth/finish` (비로그인 공개, no-store)

```jsonc
// 요청
{ "username": "위와 동일 값", "ke3": "<base64url KE3>", "transcriptId": "<start 응답의 값>" }
// 응답 200
{ "token": "...", "stepUpChallenge"? : { "required": true, "methods": string[], "expiresAt": string|null } }
// 오류: 401(프로토콜 실패/KE3 불일치) 403(리스크 정책 거부) 429 503 — 모두 {"error": "..."}
// 성공 시 Set-Cookie 로 HttpOnly 세션 쿠키가 내려옴(응답의 token 값은 클라이언트에 저장하지 말 것)
```

### 2.3 등록(세션 필요) — 설정 화면용

```jsonc
POST /api/opaque/register/start   // 세션 쿠키 필요
{ "registrationRequest": "<base64url RegistrationRequest>" }
→ 200 { "registrationResponse": "<base64url>", "credentialIdentifier": string, "serverIdentity": string }

POST /api/opaque/register/finish  // 세션 쿠키 필요
{ "record": "<base64url RegistrationRecord>" }
→ 201 { "registered": true }
```

- 등록은 "로그인한 본인이 자기 OPAQUE 비밀번호를 설정"하는 절차입니다. 등록 화면에서 사용자가 선택한 새 비밀번호가 여기 쓰이고, 평문은 서버로 절대 전송되지 않습니다.

## 3. 클라이언트 연산 예제 (참고: `scripts/opaque-smoke.ts` 를 그대로 벤치마킹)

```ts
import { getOpaqueConfig, OpaqueID, OpaqueClient, ScryptMemHardFn, KE2, RegistrationResponse } from "@cloudflare/opaque-ts"

const config = getOpaqueConfig(OpaqueID.OPAQUE_P256)

// base64url <-> bytes (서버와 동일 규격)
const toWire = (bytes: Uint8Array): string => { /* btoa + '-'/'_' 치환, 패딩 제거 */ }
const fromWire = (wire: string): number[] => { /* atob 기반, deserialize에는 Array.from 필요 */ }

async function opaqueSignIn(identifier: string, password: string) {
  const client = new OpaqueClient(config, ScryptMemHardFn)

  // 1) KE1 생성
  const ke1 = await client.authInit(password)
  if (ke1 instanceof Error) throw ke1

  // 2) auth/start
  const startRes = await fetch("/api/opaque/auth/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: identifier.trim().toLowerCase(), ke1: toWire(ke1.serialize()) }),
  })
  if (startRes.status === 429) return { status: "rate_limited" as const }
  if (!startRes.ok) return { status: "protocol_error" as const }
  const start = await startRes.json()

  // 3) 미등록 계정은 별도로 판별되지 않습니다. 가짜 레코드라 4)에서 그대로 실패합니다.

  // 4) KE2 대응(KE3 생성). 비밀번호 불일치·미등록·없는 계정이 모두 여기서 Error로 떨어짐
  const fin = await client.authFinish(
    KE2.deserialize(config, Array.from(fromWire(start.ke2))),
    start.serverIdentity,
    identifier.trim().toLowerCase(), // 서버 응답값이 아니라 입력한 식별자
  )
  if (fin instanceof Error) return { status: "invalid_credentials" as const }

  // 5) auth/finish
  const finishRes = await fetch("/api/opaque/auth/finish", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: identifier.trim().toLowerCase(), ke3: toWire(fin.ke3.serialize()), transcriptId: start.transcriptId }),
  })
  if (finishRes.status === 429) return { status: "rate_limited" as const }
  if (finishRes.status === 403) return { status: "denied" as const }
  if (!finishRes.ok) return { status: "protocol_error" as const }
  return { status: "ok" as const, body: await finishRes.json() } // body에 stepUpChallenge 있을 수 있음
}
```

**주의:** `authFinish` 호출마다 새 `OpaqueClient` 인스턴스를 쓰고, KE1→KE3 사이에 같은 인스턴스를 재사용하세요. 실패 시 절대 같은 transcript를 재사용하지 말고 처음부터 다시.

## 4. 로그인 화면(`web/src/features/auth/login-page.tsx`) 수정 사항

- `handlePassword`에서 `authClient.signIn.email(...)` / `authClient.signIn.username(...)` 호출을 **완전히 제거**합니다(해당 서버 경로는 이제 404).
- 위 `opaqueSignIn(identifier, password)`를 첫 시도로 사용.
- 결과 분기:
  - `ok` + `body.stepUpChallenge?.required === true` → 기존의 `TwoFactorForm`을 보여주고 `methods: body.stepUpChallenge.methods` 를 전달(스텝업 챌린지는 세겸 이후 2차 인증으로 완료됩니다; `TwoFactorForm.onVerified` → `finish()`).
  - `ok` (step-up 없음) → 기존 `finish()` (session 쿼리 invalidate + redirect).
  - `invalid_credentials` → "비밀번호가 올바르지 않습니다." 틀린 비밀번호, 미등록 계정, 없는 계정이 모두 이 하나의 결과입니다(구현: `web/src/lib/opaque.ts`).
  - `rate_limited` → "시도가 너무 많습니다..."(기존 429 메시지 그대로)
  - `denied` → 기존 403 메시지 "이 계정으로는..."
  - `protocol_error` → "지금은 로그인할 수 없습니다..." 후 재시도 버튼
- 패스키 로그인은 그대로 유지(서버 차단 없음).
- UI/에러 처리/스피너 등 기존 구조를 유지하고, 제출 시 `password` state를 즉시 비우세요.

**분기 불허:** 로그인이 실패했다고 평문 `/sign-in/email`로 폴백하지 마세요. 그 경로는 운영 배포에서 404이며, 폴백을 넣는 순간 평문이 와이어로 나갑니다. 미등록 계정의 최초 진입은 운영 플로우 이슈로 서버팀과 별도로 논의합니다(§7).

## 5. 등록 화면(신규)

설정(내 계정) 페이지에 "OPAQUE 비밀번호 등록/변경" 추가:

1. 새 비밀번호 입력(2회) → `client.registerInit(password)` → `POST /api/opaque/register/start` → `client.registerFinish(RegistrationResponse.deserialize(config, Array.from(fromWire(res.registrationResponse))), res.serverIdentity, res.credentialIdentifier)` → `POST /api/opaque/register/finish`.
2. 성공 시 토스트/완료 안내. 401이면 세션 만료 → 재로그인 유도.
3. 등록 여부 표시를 위한 읽기 전용 정보가 필요하면 서버 팀에 "내 OPAQUE 등록 상태 조회 엔드포인트" 요청하세요(현재 없음 — 임의로 다른 API를 건드리지 말 것).

## 6. 보안 요구사항 (검수 기준)

1. **네크워크 탭에서 로그인 시도 시**, 두 요청(`auth/start`, `auth/finish`)의 payload에 비밀번호/파생값이 어디에도 없어야 함.
2. 비밀번호는 `opaqueSignIn` 호출 인자로만 존재, 절대 쿠키/localStorage/상태에 저장 금지, 로그 금지.
3. 실패 응답 문구는 계정 열거 방지 원칙 유지(존재하지 않는 계정과 틀린 비밀번호가 같은 메시지).
4. 409 케이스 무시 말 것: 429(rate limit), 403(gate deny), 401(KE3 실패)은 서로 다른 UX를 내야 함.
5. `bun run lint`, `bun run build` (web 워크스페이스) 통과.

## 7. 열린 이슈(서버팀과 합의 필요 — 임의처리 금지)

- **미등록 계정의 최초 로그인 경로**: OPAQUE 등록은 세션이 있어야 가능(`register/*`는 세션 필요). 평문 로그인이 차단된 지금, OPAQUE 미등록 + 패스키 미등록 계정은 로그인 방법이 없음. 운영 정책(예: 관리자 초대 → 임시 활성화 세션에서 OPAQUE 등록 강제)을 서버팀이 정하는 동안, 이런 계정은 프론트에서 "비밀번호가 올바르지 않습니다."로 보입니다(계정 열거 방지 때문에 구분 불가).
- OPAQUE 등록 상태 조회 엔드포인트 부재(§5.3).

## 8. 검증 절차

1. 로컬 백엔드: `bun run dev:local` (`.dev.vars`에 `ALLOW_PLAINTEXT_PASSWORD_LOGIN=true` 는 스모크 스크립트용으로만 존재 — 이 값으로 프론트 폴백 경로를 만들지 마세요).
2. 웹: `cd web && bun install && bun run dev` (`/api/*`는 `localhost:8787`로 프록시됨).
3. 시나리오:
   - 정상 로그인 → 세션 쿠키 확인 → 이동 확인
   - 틀린 비밀번호 → "아이디 또는 비밀번호가..." 메시지
   - 미등록 계정 → 동일 메시지
   - step-up 응답 시 TwoFactorForm 동작
   - 여러 번 실패 → 429 문구
   - 서버 회귀 확인: `bun run scripts/opaque-smoke.ts` 계속 PASS
